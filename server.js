// server.js
import express from "express";
import path, { dirname } from "path";
import { fileURLToPath } from "url";
import { config as dotenvConfig } from "dotenv";
import { CosmosClient } from "@azure/cosmos";
import { DefaultAzureCredential } from "@azure/identity";
import nodemailer from "nodemailer";
import session from 'express-session';
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from 'uuid';
import {EmailClient} from "@azure/communication-email";

// Enable .env support (for local development)
dotenvConfig();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const app = express();
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Get environment variables
const endpoint = process.env.COSMOSDB_ENDPOINT;
const useManagedIdentity = process.env.USE_MI === "true";

let cosmosClient;

if (useManagedIdentity) {
  // Use Managed Identity when deployed
  const credential = new DefaultAzureCredential();
  cosmosClient = new CosmosClient({ endpoint, aadCredentials: credential });
} else {
  // Local dev: use connection string (COSMOSDB_CONN)
  const conn = process.env.COSMOSDB_CONN;
  if (!conn) {
    throw new Error("Missing COSMOSDB_CONN environment variable.");
  }
  cosmosClient = new CosmosClient(conn);
}

let emailClient;
try {
    const connectionString = process.env.ACS_CONNECTION_STRING;
    if (!connectionString) {
        throw new Error("ACS_CONNECTION_STRING is not defined in environment variables.");
    }
    emailClient = new EmailClient(connectionString);
    console.log("Azure Communication Services Email Client initialized.");

    // --- Updated check for v1.0.0 SDK ---
    if (typeof emailClient.beginSend !== 'function') {
         console.error("CRITICAL ERROR: emailClient.beginSend is not a function after initialization. Check SDK version and import.");
         emailClient = null; // Mark as unusable
         // Optionally, you might want to exit here if email is critical
         // process.exit(1);
    } else {
        console.log("emailClient.beginSend method confirmed.");
    }
    // --- End of updated check ---

} catch (err) {
    console.error("Failed to initialize Azure Communication Services Email Client:", err.message);
    emailClient = null; // Explicitly set to null on error
    // Handle the case where emailClient is null wherever it's used
    // process.exit(1); // Consider exiting if email is essential
}

const calcDatabase = cosmosClient.database("CalculatorConfigDB");
const discountContainer = calcDatabase.container("Discounts");
const volumePricingContainer = calcDatabase.container("VolumePricing");
const ppusContainer = calcDatabase.container("PPUs");

const customerDatabase = cosmosClient.database("CustomerInfo");
const customerContainer = customerDatabase.container("CustomerInfo");

const adminConfigContainer=customerDatabase.container("adminConfig");
const formConfigContainer = customerDatabase.container("FormConfig");

const siteStylesContainer = calcDatabase.container("SiteStyles");
const promoCodesContainer = calcDatabase.container("PromoCodes");


// Helper function to send emails (add this after the emailClient initialization)
async function sendEmailWithACS(emailMessage) {
    if (!emailClient) {
        throw new Error("Email client is not initialized.");
    }
    
    try {
        // Use beginSend for v1.0.0
        const poller = await emailClient.beginSend(emailMessage);
        const result = await poller.pollUntilDone();
        return result;
    } catch (error) {
        console.error("Email sending error:", error);
        throw error;
    }
}

async function getOrCreateDiscountRules() {
  try {
    // Attempt to read the existing document
    const { resource: discountDoc } = await discountContainer
      .item("discount-rules", "rules") // item(id, partitionKey)
      .read();

    if (discountDoc) {
      // Document exists, return it
      console.log("Found existing discount rules in database.");
      return discountDoc;
    }

    // Document does not exist, create default
    console.log("Discount rules not found. Creating default document.");
    const defaultDiscountDoc = {
      id: "discount-rules",
      rules: "rules", // Partition key value
      commitments: {
        "1_year": 0,
        "2_year": 0.05,
        "3_year": 0.13,
        "4_year": 0.2,
        "5_year": 0.28
      },
      additionalDiscount: {
        "Title": "Additional discount",
        "additionalDiscountAmount": 0.2
      }
    };

    const { resource: createdDoc } = await discountContainer.items.create(defaultDiscountDoc);
    console.log("Default discount rules created successfully.");
    return createdDoc;

  } catch (err) {
    console.error("Error in getOrCreateDiscountRules:", err.message);
    // Depending on your preference, you might want to throw the error
    // or return null/default values to let the route handle it gracefully.
    // For now, re-throwing to let the route's catch block handle it.
    throw err;
  }
}

//salasanan setuppeja
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultsecret',
    resave: false,
    saveUninitialized: true,
    cookie: {                //orderAdminin maksimi session pituus
      maxAge: 15 * 60 * 1000, //huom. lasketaan millisekunneissa, eli näyttää tyhmältä sen takia.
   },})
);

//haetaan tarvittu salasana orderAdminiin
app.get('/initAdmin', async (req, res) => {
  try {
    const defaultPassword = await bcrypt.hash(process.env.DEFAULT_ADMIN_PASSWORD, 10);
    
    const adminConfig = {
      id: "adminCredentials",
      adminEmails: [process.env.DEFAULT_ADMIN_EMAIL], // Array of authorized emails
      adminPassword: defaultPassword
    };

    await adminConfigContainer.items.upsert(adminConfig);
    res.send("Admin configuration initialized successfully");
  } catch (err) {
    console.error("Error initializing admin:", err);
    res.status(500).send("Error initializing admin configuration");
  }
});


app.get("/adminEmails", /*requireOrderAdminOTP*/ async (req, res) => {
    try {
        const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();
        const adminEmails = config?.adminEmails || [];

        res.render("adminEmails", {
            adminEmails: adminEmails,
            message: req.query.message || null,
            error: req.query.error || null
        });
    } catch (err) {
        console.error("Error fetching admin emails:", err);
        res.status(500).render("adminEmails", {
            adminEmails: [],
            message: null,
            error: "Failed to load admin emails."
        });
    }
});

// POST /adminEmails/add - Add a new admin email
app.post("/adminEmails/add", /*requireOrderAdminOTP*/ async (req, res) => { // Use requireOrderAdminOTP for security
    const newEmail = req.body.newEmail?.trim();

    if (!newEmail) {
        return res.redirect("/adminEmails?error=" + encodeURIComponent("Email cannot be empty."));
    }

    // Basic email format validation (you can use a library like 'validator' for more robust checks)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(newEmail)) {
         return res.redirect("/adminEmails?error=" + encodeURIComponent("Invalid email format."));
    }

    try {
        const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

        if (!config) {
             return res.redirect("/adminEmails?error=" + encodeURIComponent("Admin configuration not found."));
        }

        // Check if email already exists
        if (config.adminEmails && config.adminEmails.includes(newEmail)) {
             return res.redirect("/adminEmails?message=" + encodeURIComponent("Email already exists."));
        }

        // Add the new email
        if (!config.adminEmails) {
            config.adminEmails = [];
        }
        config.adminEmails.push(newEmail);

        // Save back to Cosmos DB
        await adminConfigContainer.items.upsert(config);

        res.redirect("/adminEmails?message=" + encodeURIComponent("Email added successfully."));
    } catch (err) {
        console.error("Error adding admin email:", err);
        res.redirect("/adminEmails?error=" + encodeURIComponent("Failed to add email."));
    }
});

// POST /adminEmails/update - Update an existing admin email
// Note: This implementation updates the email based on its index in the array.
app.post("/adminEmails/update", /*requireOrderAdminOTP*/ async (req, res) => {
    const updatedEmails = req.body.emails; // This will be an object like { '0': 'newemail1@example.com', '1': 'newemail2@example.com' }

    if (!updatedEmails || typeof updatedEmails !== 'object') {
         return res.redirect("/adminEmails?error=" + encodeURIComponent("Invalid data received for update."));
    }

    try {
        const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

        if (!config) {
             return res.redirect("/adminEmails?error=" + encodeURIComponent("Admin configuration not found."));
        }

        // Get the current list of emails
        let currentEmails = config.adminEmails || [];

        // Update emails based on index
        for (const indexStr in updatedEmails) {
            const index = parseInt(indexStr, 10);
            const newEmail = updatedEmails[indexStr]?.trim();

            if (isNaN(index) || index < 0 || index >= currentEmails.length || !newEmail) {
                console.warn(`Skipping invalid update for index ${indexStr} or email ${newEmail}`);
                continue; // Skip invalid entries
            }

            // Basic email format validation (you can use a library like 'validator' for more robust checks)
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(newEmail)) {
                 // If any email is invalid, stop and show error for that specific one if possible, or a general one.
                 // For simplicity, we'll redirect with a general error. A more complex UI could highlight the field.
                 return res.redirect("/adminEmails?error=" + encodeURIComponent(`Invalid email format for update: ${newEmail}`));
            }

            // Check if the new email already exists elsewhere in the list (excluding its own index)
            if (currentEmails.some((email, i) => email === newEmail && i !== index)) {
                 return res.redirect("/adminEmails?error=" + encodeURIComponent(`Email ${newEmail} already exists in the list.`));
            }

            currentEmails[index] = newEmail;
        }

        // Update the config object
        config.adminEmails = currentEmails;

        // Save back to Cosmos DB
        await adminConfigContainer.items.upsert(config);

        res.redirect("/adminEmails?message=" + encodeURIComponent("Email(s) updated successfully."));
    } catch (err) {
        console.error("Error updating admin emails:", err);
        res.redirect("/adminEmails?error=" + encodeURIComponent("Failed to update email(s)."));
    }
});

// POST /adminEmails/delete/:index - Delete an admin email by its index
app.post("/adminEmails/delete/:index", /*requireOrderAdminOTP*/ async (req, res) => { 
    const indexToDelete = parseInt(req.params.index, 10);

    if (isNaN(indexToDelete) || indexToDelete < 0) {
         return res.redirect("/adminEmails?error=" + encodeURIComponent("Invalid index for deletion."));
    }


    try {
        const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

        if (!config) {
             return res.redirect("/adminEmails?error=" + encodeURIComponent("Admin configuration not found."));
        }

        const currentEmails = config.adminEmails || [];

        if (indexToDelete >= currentEmails.length) {
             return res.redirect("/adminEmails?error=" + encodeURIComponent("Email index out of range."));
        }

        // Remove the email at the specified index
        currentEmails.splice(indexToDelete, 1);

        // Update the config object
        config.adminEmails = currentEmails;

        // Save back to Cosmos DB
        await adminConfigContainer.items.upsert(config);

        res.redirect("/adminEmails?message=" + encodeURIComponent("Email deleted successfully."));
    } catch (err) {
        console.error("Error deleting admin email:", err);
        res.redirect("/adminEmails?error=" + encodeURIComponent("Failed to delete email."));
    }
});

// --- End of new routes ---

// ... (rest of your server.js code) ...

// GET /verify-email – page where admin inputs email
app.get('/verify-email', (req, res) => {
  res.render('verifyEmail', { error: null });
});

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    try {
        // --- ADD THIS CHECK ---
        if (!emailClient) {
            console.error("Email client is not initialized. Cannot send OTP.");
            return res.render('verifyEmail', { error: "Email service is currently unavailable. Please try again later." });
        }
        // --- END ADD CHECK ---

        const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();
        if (!config.adminEmails.includes(email)) {
            return res.render('verifyEmail', { error: "Email not authorized." });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        req.session.otp = otp;
        req.session.otpEmail = email;
        req.session.otpExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

        const senderAddress = process.env.EMAIL_USER;
        if (!senderAddress) {
            throw new Error("EMAIL_USER (sender address) is not defined in environment variables for ACS.");
        }

        const emailMessage = {
            senderAddress: senderAddress,
            recipients: {
                to: [{ address: email }],
            },
            content: {
                subject: "Your One-Time Passcode (OTP)",
                plainText: `Your OTP is: ${otp}`,
            },
        };

        // --- Updated to use the helper function ---
        const sendResult = await sendEmailWithACS(emailMessage);
        console.log("OTP email sent successfully. Operation ID:", sendResult.id);
        res.render('enterOtp', { email, error: null });
    } catch (err) {
        console.error("Error sending OTP:", err.message);
        // Differentiate between ACS errors and others if needed
        if (err.name === 'RestError') {
            console.error("ACS Email Error Details:", err);
        }
        res.render('verifyEmail', { error: "Error sending OTP. Please try again." });
    }
});

//otp:n varmistus
app.post('/verify-otp', (req, res) => {
  const { otp, email } = req.body;

  if (
    req.session.otp !== otp ||
    req.session.otpEmail !== email ||
    Date.now() > req.session.otpExpires
  ) {
    return res.render('enterOtp', { email, error: "Invalid or expired OTP." });
  }

  // Success
  req.session.orderAdminVerified = true;

  // Clean up OTP
  delete req.session.otp;
  delete req.session.otpEmail;
  delete req.session.otpExpires;

  res.redirect('/orderAdmin');
});

//uusi salasana teknologia
app.post('/verifyResetCode', async (req, res) => {
  const { email, code, newPassword } = req.body;

  // Validate the reset code
  if (
    req.session.resetCode !== code ||
    req.session.resetEmail !== email ||
    Date.now() > req.session.codeExpires
  ) {
    return res.render('resetPassword', { email, error: "Invalid or expired code." });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Get the current config
    const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();
    
    // Update the password
    config.adminPassword = hashedPassword;
    
    // Save back to Cosmos DB
    await adminConfigContainer.items.upsert(config);

    // Clean up session
    delete req.session.resetCode;
    delete req.session.resetEmail;
    delete req.session.codeExpires;

    res.redirect('/login');
  } catch (err) {
    console.error("Password reset failed:", err);
    res.render('resetPassword', { email, error: "Could not update password." });
  }
});


//salasanan vaihtamiseen
app.post('/requestResetCode', async (req, res) => {
    const { email } = req.body;
    try {
        // --- ADD THIS CHECK ---
        if (!emailClient) {
            console.error("Email client is not initialized. Cannot send reset code.");
            return res.render('login', { error: "Email service is currently unavailable. Please try again later." });
        }
        // --- END ADD CHECK ---

        // ... rest of the /requestResetCode logic ...
         const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();
        if (!config.adminEmails.includes(email)) {
            return res.render('login', { error: "Email not authorized." });
        }
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // Store code in session
        req.session.resetCode = code;
        req.session.resetEmail = email;
        req.session.codeExpires = Date.now() + 15 * 60 * 1000; // 15 min expiry

        const senderAddress = process.env.EMAIL_USER;
        if (!senderAddress) {
            throw new Error("EMAIL_USER (sender address) is not defined in environment variables for ACS.");
        }

        const emailMessage = {
            senderAddress: senderAddress,
            recipients: {
                to: [{ address: email }],
            },
            content: {
                subject: "Your Admin Reset Code",
                plainText: `Your code is: ${code}`,
            },
        };

        // --- Updated to use the helper function ---
        const sendResult = await sendEmailWithACS(emailMessage);
        console.log("Reset code email sent successfully. Operation ID:", sendResult.id);
        res.render('resetPassword', { email, error: null });

    } catch (err) {
        console.error("Reset code error:", err);
         // Differentiate between ACS errors and others if needed
        if (err.name === 'RestError') {
            console.error("ACS Email Error Details:", err);
        }
        res.render('login', { error: "Failed to send reset code." });
    }
});

// GET /initFormConfig - Initialize form configurations with defaults
app.get("/initFormConfig", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const defaultConfigs = [
      // Form title
      {
        id: "formTitle",
        fieldName: "formTitle",
        title: "Order Form",
        placeholder: "",
        required: false
      },
      
      // Section titles
      {
        id: "ordererSectionTitle",
        fieldName: "ordererSectionTitle",
        title: "Orderer Information",
        placeholder: "",
        required: false
      },
      {
        id: "partnerSectionTitle",
        fieldName: "partnerSectionTitle",
        title: "Partner Information",
        placeholder: "",
        required: false
      },
      {
        id: "customerSectionTitle",
        fieldName: "customerSectionTitle",
        title: "Customer Information",
        placeholder: "",
        required: false
      },
      {
        id: "subscriptionSectionTitle",
        fieldName: "subscriptionSectionTitle",
        title: "Fresh Subscription",
        placeholder: "",
        required: false
      },

      // Orderer Information Fields
      {
        id: "ordererName",
        fieldName: "ordererName",
        title: "Orderer Name",
        placeholder: "Name of the person making the order",
        required: true
      },
      {
        id: "ordererEmail",
        fieldName: "ordererEmail",
        title: "Orderer Email",
        placeholder: "Email of the person making the order",
        required: true
      },

      // Partner Information Fields
      {
        id: "partnerCompany",
        fieldName: "partnerCompany",
        title: "Partner Company",
        placeholder: "Partner company name",
        required: true
      },
      {
        id: "partnerSignatory",
        fieldName: "partnerSignatory",
        title: "Partner Signatory",
        placeholder: "Partner signatory name, position and email",
        required: true
      },
      {
        id: "partnerContactName",
        fieldName: "partnerContactName",
        title: "Partner Contact Name",
        placeholder: "Partner contact name",
        required: true
      },
      {
        id: "partnerContactPhone",
        fieldName: "partnerContactPhone",
        title: "Partner Contact Phone",
        placeholder: "Partner contact phone number",
        required: true
      },
      {
        id: "partnerContactEmail",
        fieldName: "partnerContactEmail",
        title: "Partner Contact Email",
        placeholder: "Partner contact email",
        required: true
      },

      // Customer Information Fields
      {
        id: "customerCompany",
        fieldName: "customerCompany",
        title: "Customer Company",
        placeholder: "Customer company name",
        required: true
      },
      {
        id: "customerAddress",
        fieldName: "customerAddress",
        title: "Customer Address",
        placeholder: "Registered address",
        required: true
      },
      {
        id: "customerBusinessNumber",
        fieldName: "customerBusinessNumber",
        title: "Business Number",
        placeholder: "Business number",
        required: true
      },
      {
        id: "customerContactName",
        fieldName: "customerContactName",
        title: "Contact Name",
        placeholder: "Customer contact name",
        required: true
      },
      {
        id: "customerContactEmail",
        fieldName: "customerContactEmail",
        title: "Contact Email",
        placeholder: "Customer contact email",
        required: true
      },
      {
        id: "customerContactPhone",
        fieldName: "customerContactPhone",
        title: "Contact Phone",
        placeholder: "Customer contact phone number",
        required: true
      },

      // Subscription Information Fields
      {
        id: "numUsers",
        fieldName: "numUsers",
        title: "Number of Users",
        placeholder: "Number of users",
        required: true
      },
      {
        id: "currency",
        fieldName: "currency",
        title: "Currency",
        placeholder: "Select currency",
        required: true
      },
      {
        id: "customerPrice",
        fieldName: "customerPrice",
        title: "Customer Price",
        placeholder: "Customer price",
        required: true
      },
      {
        id: "startDate",
        fieldName: "startDate",
        title: "Start Date",
        placeholder: "Start date",
        required: true
      },
      {
        id: "initialTerm",
        fieldName: "initialTerm",
        title: "Initial Term",
        placeholder: "Initial term (months)",
        required: true
      },
      {
        id: "tenantURL",
        fieldName: "tenantURL",
        title: "Tenant URL",
        placeholder: "Client tenant URL",
        required: true
      }
    ];

    // Upsert all configurations in parallel
    await Promise.all(defaultConfigs.map(config => 
      formConfigContainer.items.upsert(config)
    ));

    res.redirect("/formConfig?message=" + 
      encodeURIComponent("Form configurations initialized with defaults"));
  } catch (err) {
    console.error("Error initializing form configs:", err);
    res.redirect("/formConfig?message=" + 
      encodeURIComponent("Error initializing form configurations: " + err.message));
  }
});

// GET /formConfig - Retrieve all form field configurations
app.get("/formConfig", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { resources: configs } = await formConfigContainer.items.query({
      query: "SELECT * FROM c"
    }).fetchAll();

    // Convert array of configs to an object by field name for easier access
    const configMap = {};
    configs.forEach(config => {
      configMap[config.fieldName] = config;
    });

    res.render("formConfig", { 
      configs: configMap,
      message: req.query.message || null
    });
  } catch (err) {
    console.error("Error fetching form configs:", err);
    res.status(500).render("formConfig", {
      configs: {},
      message: "Error loading form configurations"
    });
  }
});

// POST /updateFormConfig - Update form field configurations
app.post("/updateFormConfig", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const updates = [];
    
    // Process each field configuration
    for (const fieldName in req.body.fields) {
      const fieldConfig = req.body.fields[fieldName];
      
      const configItem = {
        id: fieldName,
        fieldName: fieldName,
        title: fieldConfig.title,
        placeholder: fieldConfig.placeholder,
        required: fieldConfig.required === "on"
      };

      updates.push(formConfigContainer.items.upsert(configItem));
    }

    await Promise.all(updates);
    res.redirect("/formConfig?message=" + encodeURIComponent("Form configurations updated successfully"));
  } catch (err) {
    console.error("Error updating form configs:", err);
    res.redirect("/formConfig?message=" + encodeURIComponent("Error updating form configurations"));
  }
});


//haetaan quote ID:llä
app.get("/get-quote/:quoteId", async (req, res) => {
  try {
    const quotesContainer = customerDatabase.container("Quotes");
    const { resource: quote } = await quotesContainer.item(req.params.quoteId, req.params.quoteId).read();
    if (!quote) {
      return res.status(404).json({ 
        success: false,
        error: "Quote not found",
        message: "No quote found with the provided code. Please check the code and try again."
      });
    }
    res.json({
      success: true,
      customerContactName: quote.QuoteCustomerName || '', // Changed to match field name
      numUsers: quote.QuoteUserAmount || '',
      currency: quote.QuoteCurrency || '',
      QuotePrice: quote.QuotePrice || {}, // Include full price object
      QuoteCustomerEmail: quote.QuoteCustomerEmail || '' // Include email
    });
  } catch (err) {
    console.error("Error fetching quote:", err);
    if (err.code === 404) {
      return res.status(404).json({ 
        success: false,
        error: "Quote not found",
        message: "No quote found with the provided code. Please check the code and try again."
      });
    }
    res.status(500).json({ 
      success: false,
      error: "Server error",
      message: "Failed to fetch quote. Please try again later."
    });
  }
});

// Modify your /form route to include field configurations
app.get("/form", requireAuth, async (req, res) => {
  try {
    const tooltipIds = [
      "ordererInfo",
      "partnerInfo",
      "customerInfo",
      "subscriptionInfo"
    ];

    const tooltips = {};
    for (const id of tooltipIds) {
      const { resource } = await customerDatabase
        .container("Tooltips")
        .item(id, id)
        .read();
      tooltips[id] = resource?.text || "";
    }

    // Fetch form field configurations
    const { resources: fieldConfigs } = await formConfigContainer.items.query({
      query: "SELECT * FROM c"
    }).fetchAll();

    const fieldConfigMap = {};
    fieldConfigs.forEach(config => {
      fieldConfigMap[config.fieldName] = config;
    });

    res.render("form", { 
      tooltips,
      fieldConfigs: fieldConfigMap
    });
  } catch (err) {
    console.error("Error loading form:", err.message);
    res.render("form", { 
      tooltips: {},
      fieldConfigs: {}
    });
  }
});

// Routes

// GET /
app.get("/", (req, res) => {
  res.render("index");
});


// GET /calculator
app.get("/calculator", async (req, res) => {
  try {
    // --- Use the helper function ---
    const discountDoc = await getOrCreateDiscountRules();

    if (!discountDoc || !discountDoc.commitments) {
      // This check is mostly redundant now due to the helper's logic,
      // but kept as a safeguard.
      throw new Error("Failed to load or create discount document with commitments field.");
    }
    // --- End of using helper function ---

    const commitmentOptions = Object.entries(discountDoc.commitments).map(([key, value]) => ({
      label: key.replace('_', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase()), // "1_year" → "1 Year"
      value: value * 100,
      key: key
    }));

    // --- Fetch the title for the additional discount ---
    let additionalDiscountTitle = "Eligible for discount?"; // Default title
    let additionalDiscountValue = 0; // Default value
    if (discountDoc.additionalDiscount) {
        // If the structure exists, use it
        additionalDiscountTitle = discountDoc.additionalDiscount.Title || "Eligible for discount?";
        additionalDiscountValue = (discountDoc.additionalDiscount.additionalDiscountAmount || 0) * 100;
    }
    // --- End of fetching additional discount data ---

    res.render("calculator", {
      commitmentOptions,
      additionalDiscountTitle,
      additionalDiscountValue
    });
  } catch (err) {
    console.error("Failed to load discount options:", err.message);
    // You might choose to render the calculator with default *UI* values here
    // instead of sending a 500, depending on desired robustness.
    res.status(500).send("Failed to load discount options");
  }
});




//authentikointia loginille
async function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }

  try {
    const { resource: config } = await adminConfigContainer
      .item("adminCredentials", "adminCredentials")
      .read();

    if (!config.adminPassword || config.adminPassword === "") {
      req.session.authenticated = true;
      return next();
    } else {
      return res.redirect("/login");
    }
  } catch (err) {
    console.error("Auth check failed:", err);
    return res.redirect("/login");
  }
}

// GET /info
app.get("/info", async (req, res) => {
  try {
    // Fetch form field configurations
    const { resources: fieldConfigs } = await formConfigContainer.items.query({
      query: "SELECT * FROM c"
    }).fetchAll();

    // Organize by section using titles
    const sections = {
      orderer: {
        title: fieldConfigs.find(c => c.fieldName === 'ordererSectionTitle')?.title || 'Orderer Information',
        fields: [
          fieldConfigs.find(c => c.fieldName === 'ordererName'),
          fieldConfigs.find(c => c.fieldName === 'ordererEmail')
        ].filter(Boolean)
      },
      partner: {
        title: fieldConfigs.find(c => c.fieldName === 'partnerSectionTitle')?.title || 'Partner Information',
        fields: [
          fieldConfigs.find(c => c.fieldName === 'partnerCompany'),
          fieldConfigs.find(c => c.fieldName === 'partnerSignatory'),
          fieldConfigs.find(c => c.fieldName === 'partnerContactName'),
          fieldConfigs.find(c => c.fieldName === 'partnerContactPhone'),
          fieldConfigs.find(c => c.fieldName === 'partnerContactEmail')
        ].filter(Boolean)
      },
      customer: {
        title: fieldConfigs.find(c => c.fieldName === 'customerSectionTitle')?.title || 'Customer Information',
        fields: [
          fieldConfigs.find(c => c.fieldName === 'customerCompany'),
          fieldConfigs.find(c => c.fieldName === 'customerAddress'),
          fieldConfigs.find(c => c.fieldName === 'customerBusinessNumber'),
          fieldConfigs.find(c => c.fieldName === 'customerContactName'),
          fieldConfigs.find(c => c.fieldName === 'customerContactEmail'),
          fieldConfigs.find(c => c.fieldName === 'customerContactPhone')
        ].filter(Boolean)
      },
      subscription: {
        title: fieldConfigs.find(c => c.fieldName === 'subscriptionSectionTitle')?.title || 'Subscription Information',
        fields: [
          fieldConfigs.find(c => c.fieldName === 'numUsers'),
          fieldConfigs.find(c => c.fieldName === 'currency'),
          fieldConfigs.find(c => c.fieldName === 'customerPrice'),
          fieldConfigs.find(c => c.fieldName === 'startDate'),
          fieldConfigs.find(c => c.fieldName === 'initialTerm'),
          fieldConfigs.find(c => c.fieldName === 'tenantURL')
        ].filter(Boolean)
      }
    };

    res.render("info", { sections });
  } catch (err) {
    console.error("Error loading form info:", err);
    // Fallback with empty sections if there's an error
    res.render("info", {
      sections: {
        orderer: { title: 'Orderer Information', fields: [] },
        partner: { title: 'Partner Information', fields: [] },
        customer: { title: 'Customer Information', fields: [] },
        subscription: { title: 'Subscription Information', fields: [] }
      }
    });
  }
});

// GET /login /formille
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// POST /login
app.post('/login', async (req, res) => {
  const { password } = req.body;

  try {
    const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

    if (!config) {
      return res.render('login', { error: 'Admin configuration not found' });
    }

    // If password in DB is null or empty string, allow automatic login
    if (!config.adminPassword || config.adminPassword === "") {
      req.session.authenticated = true;
      return res.redirect('/form');
    }

    const match = await bcrypt.compare(password, config.adminPassword);

    if (match) {
      req.session.authenticated = true;
      res.redirect('/form');
    } else {
      res.render('login', { error: 'Invalid password' });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render('login', { error: 'Login failed' });
  }
});

function requireOrderAdminOTP (req, res, next) {                                                              //OTA POIS KOMMENTTI LOPETTAESSA
  if (req.session && req.session.orderAdminVerified) {
    return next();
  }
  res.redirect('/verify-email');
}

/// GET /orderAdmin
// GET /orderAdmin
app.get("/orderAdmin", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const searchTerm = req.query.search || "";
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    let querySpec;
    if (searchTerm) {
      querySpec = {
        query: "SELECT * FROM c WHERE CONTAINS(c.customerCompany, @term) OR CONTAINS(c.ordererName, @term)",
        parameters: [{ name: "@term", value: searchTerm }]
      };
    } else {
      querySpec = { query: "SELECT * FROM c" };
    }

    const { resources: allCustomers } = await customerContainer.items.query(querySpec).fetchAll();

    // Filter out the sysemail document and system fields
    const filteredCustomers = allCustomers
      .filter(c => c.id !== "sysemail")
      .map(({ _rid, _self, _etag, _attachments, _ts, ...rest }) => rest);

    // Fetch sysemail document for current email
    const { resources: emailDoc } = await customerContainer.items
      .query({
        query: "SELECT * FROM c WHERE c.id = @id",
        parameters: [{ name: "@id", value: "sysemail" }]
      })
      .fetchAll();

    const currentEmail = emailDoc[0]?.email || "";

    // Paginate results
    const paginatedCustomers = filteredCustomers.slice(offset, offset + limit);
    const totalPages = Math.ceil(filteredCustomers.length / limit);
    
    // Fetch tooltips
    const tooltipIds = ["ordererInfo", "partnerInfo", "customerInfo", "subscriptionInfo"];
    const tooltips = {};
    const container = customerDatabase.container("Tooltips");

    for (const id of tooltipIds) {
      try {
        const { resource } = await container.item(id, id).read();
        tooltips[id] = resource?.text || "";
      } catch {
        tooltips[id] = ""; // default if missing
      }
    }

    // Fetch form configurations
    const { resources: configs } = await formConfigContainer.items.query({
      query: "SELECT * FROM c"
    }).fetchAll();

    // Convert array of configs to an object by field name for easier access
    const configMap = {};
    configs.forEach(config => {
      configMap[config.fieldName] = config;
    });

    res.render("orderAdmin", {
      customers: paginatedCustomers,
      message: null,
      currentPage: page,
      totalPages: totalPages,
      searchTerm,
      limit,
      currentEmail,
      emailMessage: req.query.emailMessage || null,
      tooltips,
      tooltipsMsg: req.query.tooltipsMsg || null,
      configs: configMap
    });

  } catch (err) {
    console.error("Error fetching customer data:", err.message);
    res.status(500).render("orderAdmin", {
      customers: [],
      message: "Error loading customer data",
      currentPage: 1,
      totalPages: 1,
      searchTerm: "",
      currentEmail: "",
      emailMessage: "Error fetching system email",
      tooltips: {
        ordererInfo: "",
        partnerInfo: "",
        customerInfo: "",
        subscriptionInfo: ""
      },
      tooltipsMsg: null,
      configs: {}
    });
  }
});

//for updating tooltips to cosmos db
app.post("/updateTooltips", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const container = customerDatabase.container("Tooltips");
    const updateOps = [
      { id: "ordererInfo", text: req.body.ordererInfo },
      { id: "partnerInfo", text: req.body.partnerInfo },
      { id: "customerInfo", text: req.body.customerInfo },
      { id: "subscriptionInfo", text: req.body.subscriptionInfo },
    ];

    for (const t of updateOps) {
      await container.items.upsert({ id: t.id, text: t.text });
    }

    res.redirect("/orderAdmin?tooltipsMsg=" + encodeURIComponent("Tooltips updated."));
  } catch (err) {
    console.error("Tooltip update failed:", err);
    res.redirect("/orderAdmin?tooltipsMsg=" + encodeURIComponent("Error updating tooltips."));
  }
});

//log out
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// POST /updateEmail (from orderAdmin page)
app.post("/updateEmail", async (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail) {
    return res.redirect("/orderAdmin?emailMessage=" + encodeURIComponent("Email cannot be empty"));
  }

  try {
    const item = { id: "sysemail", email: newEmail };
    await customerContainer.items.upsert(item);
    res.redirect("/orderAdmin?emailMessage=" + encodeURIComponent("System email updated successfully"));
  } catch (err) {
    console.error("Failed to update sysemail:", err.message);
    res.redirect("/orderAdmin?emailMessage=" + encodeURIComponent("Failed to update system email"));
  }
});

// GET /admin - Configuration editor
app.get("/admin", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    // Fetch all required data in parallel
    const [
      discountRulesResponse,
      ppusResponse,
      volumePricingResponse,
      basePricesResponse
    ] = await Promise.all([
      discountContainer.item("discount-rules", "rules").read(),
      ppusContainer.items.query("SELECT * FROM c ORDER BY c.date DESC").fetchAll(),
      volumePricingContainer.items.query({
        query: "SELECT * FROM c WHERE c.userCount != null ORDER BY c.userCount ASC"
      }).fetchAll(),
      volumePricingContainer.items.query({
        query: "SELECT * FROM c WHERE c.id = 'BasePrices'"
      }).fetchAll()
    ]);

    // --- Modified: Process discount rules to include title and additionalDiscount ---
    const discountRules = discountRulesResponse.resource || {};
    let additionalDiscountData = {
        title: "Eligible for discount?", // Default title
        value: 0
    };
    if (discountRules.additionalDiscount) {
        // If the new structure exists, use it
        additionalDiscountData = {
            title: discountRules.additionalDiscount.Title || "Eligible for discount?",
            value: parseFloat(discountRules.additionalDiscount.additionalDiscountAmount) || 0
        };
    } else if (discountRules.currentSubscriber !== undefined) {
        // Fallback: If old structure exists, migrate it
        additionalDiscountData = {
            title: "Eligible for discount?", // Default title for migrated data
            value: parseFloat(discountRules.currentSubscriber) || 0
        };
    }
    // --- End Modification ---
    if (discountRules.commitments) {
      discountRules.commitments = Object.entries(discountRules.commitments).map(([key, value]) => ({
        key,
        name: key.replace('_', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase()),
        value: parseFloat(value) || 0
      }));
    }

    // Process PPUs
    const ppus = ppusResponse.resources[0]?.ppu || {};
    for (const currency in ppus) {
      if (ppus[currency]) {
        ppus[currency].standard = Number(ppus[currency].standard) || 0;
        if (ppus[currency].alternate) {
          ppus[currency].alternate = Number(ppus[currency].alternate) || 0;
        }
      }
    }

    // --- Modified: Process base prices and initialize if missing ---
    let basePrices = basePricesResponse.resources[0]; // Get the first (should be only) base prices document

    // Check if base prices document exists
    if (!basePrices) {
      console.log("Base prices not found in database. Initializing with default values.");
      // Define default base prices structure
      const defaultBasePrices = {
        id: "BasePrices",
        userCount: null,
        volumeDiscount: null,
        subscriptions: {
          GBP: 33,
          EUR: 37.2, // Note: These are already specified values, not calculated
          USD: 39.6  // parseFloat converts them, toFixed(2) ensures 2 decimals if needed for display [[1]]
        }
      };

      try {
        // Save the default base prices document to the database
        const { resource: createdBasePrices } = await volumePricingContainer.items.create(defaultBasePrices);
        console.log("Default base prices initialized successfully:", createdBasePrices.id);
        basePrices = createdBasePrices; // Use the newly created document
      } catch (createErr) {
        console.error("Error creating default base prices document:", createErr);
        // If creation fails, use the default object in memory for rendering
        basePrices = defaultBasePrices;
        // Optionally add a message to indicate the DB issue
        // res.locals.basePriceMessage = "Failed to save default base prices to database.";
      }
    }
    // --- End Modification ---

    // Process volume pricing tiers
    const volumePricing = volumePricingResponse.resources.map(tier => {
      const processedTier = {
        id: tier.id,
        userCount: tier.userCount,
        volumeDiscount: parseFloat(tier.volumeDiscount) || 0,
        subscriptions: tier.subscriptions || {}
      };
      return processedTier;
    });

    res.render("admin", {
      discountRules: discountRules || {
        commitments: [],
      },
      additionalDiscountData: additionalDiscountData,
      ppus: ppus || {},
      volumePricing: volumePricing || [],
      basePrices: basePrices, // Pass the potentially initialized base prices
      message: req.query.message || null,
      baseCurrency: 'GBP',
      activeStep: req.query.step ? parseInt(req.query.step) : 1
    });
  } catch (err) {
    console.error("Error loading admin data:", err);
    // Make sure error response also initializes these objects to prevent template errors
    res.status(500).render("admin", {
      discountRules: {
        commitments: [],
      },
      additionalDiscountData: {
        title: "Eligible for discount?",
        value: 0
      },
      ppus: {},
      volumePricing: [],
      basePrices: {
        id: "BasePrices",
        userCount: null,
        volumeDiscount: null,
        subscriptions: {
          GBP: 33,
          EUR: 37.2,
          USD: 39.6
        }
      },
      message: "Error loading configuration data",
      baseCurrency: 'GBP'
    });
  }
});


// POST /admin/updateVolumePricing - Ensure precision when handling discount
app.post("/admin/updateVolumePricing", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { tiers = {} } = req.body;
    const updateOps = [];

    // --- Fetch base prices only for calculations ---
    const basePricesResponse = await volumePricingContainer.items.query({
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: "BasePrices" }]
    }).fetchAll();

    const basePrices = basePricesResponse.resources[0]?.subscriptions || {};
    // --- End of Fetch base prices ---

    // Process each tier
    for (const tierId in tiers) {
      const tierData = tiers[tierId];
      const userCount = parseInt(tierData.userCount);

      // Determine volume discount - either from form or calculated from GBP price
      let volumeDiscountDecimal;
      if (tierData.volumeDiscount !== undefined) {
        // --- CRITICAL: Parse the discount percentage with maximum available precision ---
        const discountPercentStr = tierData.volumeDiscount;
        const discountPercent = parseFloat(discountPercentStr);
        if (isNaN(discountPercent)) {
            console.warn(`Invalid discount percentage received for tier ${tierId}: ${discountPercentStr}. Defaulting to 0.`);
            volumeDiscountDecimal = 0;
        } else {
            volumeDiscountDecimal = discountPercent / 100;
            volumeDiscountDecimal = Math.max(0, Math.min(1, volumeDiscountDecimal)); // Clamp between 0 and 1
        }
        console.log(`Tier ${tierId}: Received discount string: ${discountPercentStr}, Parsed decimal: ${volumeDiscountDecimal}`);
        // ---
      } else {
        // Calculate discount from GBP price if available (fallback logic)
        const gbpPrice = parseFloat(tierData.subscriptions.GBP) || 0;
        const baseGbpPrice = basePrices.GBP || 0;
        if (userCount > 0 && baseGbpPrice > 0) {
          volumeDiscountDecimal = 1 - (gbpPrice / (baseGbpPrice * userCount));
          volumeDiscountDecimal = Math.max(0, Math.min(1, volumeDiscountDecimal)); // Clamp
        } else {
          volumeDiscountDecimal = 0;
        }
      }

      const update = {
        id: tierData.id,
        userCount: userCount,
        volumeDiscount: volumeDiscountDecimal, // Store the precise decimal
        subscriptions: {}
      };

      // --- Process each currency price using the fetched basePrices ---
      for (const currency in basePrices) { // Iterate through base currencies
        const basePriceForCurrency = basePrices[currency]; // Get base price for this currency
        if (basePriceForCurrency !== undefined && basePriceForCurrency !== null) {
          // Apply the formula: final price = (user count * base price) * (1 - volume discount)
          const calculatedPrice = (userCount * basePriceForCurrency) * (1 - volumeDiscountDecimal);
          update.subscriptions[currency] = parseFloat(calculatedPrice.toFixed(2)); // Store with 2 decimals
        } else {
          // Handle case where base price for a currency might be missing
          console.warn(`Base price for currency ${currency} not found. Setting price to 0.`);
          update.subscriptions[currency] = 0;
        }
      }
      // --- End of Process each currency ---

      updateOps.push(volumePricingContainer.items.upsert(update));
    }
    await Promise.all(updateOps);
    res.redirect("/admin?step=4&message=Volume pricing updated successfully");
  } catch (err) {
    console.error("Error updating volume pricing:", err);
    res.redirect("/admin?message=Error updating volume pricing: " + encodeURIComponent(err.message));
  }
});

// POST /admin/update - save updated variables
app.post("/admin/updateDiscounts", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { commitments, additionalDiscountTitle, additionalDiscountValue } = req.body; // Changed variable names

    // Convert commitments from form data to object
    const commitmentsObj = {};
    for (const [key, value] of Object.entries(commitments)) {
      commitmentsObj[key] = parseFloat(value) / 100;
    }

    // --- Modified: Create the new additionalDiscount structure ---
    const additionalDiscountObj = {
        Title: additionalDiscountTitle || "Eligible for discount?", // Use provided title or default
        additionalDiscountAmount: parseFloat(additionalDiscountValue) / 100 // Convert from percentage
    };
    // --- End Modification ---

    const update = {
      id: "discount-rules",
      rules: "rules", // partition key
      commitments: commitmentsObj,
      // --- Removed: currentSubscriber ---
      // --- Added: additionalDiscount ---
      additionalDiscount: additionalDiscountObj
      // ---
    };

    await discountContainer.items.upsert(update);
    res.redirect("/admin?step=4&message=Discounts updated successfully");
  } catch (err) {
    console.error("Error updating discounts:", err);
    res.redirect("/admin?step=4&message=Error updating discounts: " + err.message); // Include error message
  }
});

// POST /admin/updatePPUs - WITH ERROR HANDLING
app.post("/admin/updatePPUs", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const ppus = req.body.ppus;
    const baseId = `ppu-${new Date().toISOString().split('T')[0]}`;
    let update = {
      id: baseId,
      date: new Date().toISOString(),
      ppu: ppus
    };

    try {
      await ppusContainer.items.create(update);
    } catch (createErr) {
      if (createErr.code === 409) {
        // Document exists, use upsert or create with unique ID
        update.id = `${baseId}-${Date.now()}`;
        await ppusContainer.items.create(update);
      } else {
        throw createErr;
      }
    }

    res.redirect("/admin?step=4&message=PPUs updated successfully");
  } catch (err) {
    console.error("Error updating PPUs:", err);
    res.redirect("/admin?message=Error updating PPUs: " + err.message);
  }
});

app.post("/admin/updateVolumePricing", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { tiers = {} } = req.body;
    const updateOps = [];
    
    // Get base prices and currency rates for calculations
    const basePricesResponse = await volumePricingContainer.items.query({
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: "BasePrices" }]
    }).fetchAll();
    
    const currenciesResponse = await volumePricingContainer.items.query({
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: "currencies" }]
    }).fetchAll();
    
    const basePrices = basePricesResponse.resources[0]?.subscriptions || {};
    const currencies = currenciesResponse.resources[0] || { GBP: 1.0, USD: 1.3, EUR: 1.15 };
    
    // Process each tier
    for (const tierId in tiers) {
      const tierData = tiers[tierId];
      const userCount = parseInt(tierData.userCount);
      
      // Determine volume discount - either from form or calculated from GBP price
      let volumeDiscount;
      if (tierData.volumeDiscount !== undefined) {
        // Use provided discount with 10 decimal precision
        volumeDiscount = parseFloat(tierData.volumeDiscount) / 100;
      } else {
        // Calculate discount from GBP price if available
        const gbpPrice = parseFloat(tierData.subscriptions.GBP) || 0;
        const baseGbpPrice = basePrices.GBP || 0;
        if (userCount > 0 && baseGbpPrice > 0) {
          volumeDiscount = 1 - (gbpPrice / (baseGbpPrice * userCount));
          // Ensure discount is between 0 and 1
          volumeDiscount = Math.max(0, Math.min(1, volumeDiscount));
        } else {
          volumeDiscount = 0;
        }
      }
      
      // Ensure volume discount has high precision
      volumeDiscount = parseFloat(volumeDiscount.toFixed(10));
      
      const update = {
        id: tierData.id,
        userCount: userCount,
        volumeDiscount: volumeDiscount,
        subscriptions: {}
      };
      
      // Process each currency price
      for (const currency in tierData.subscriptions) {
        if (currency === 'GBP') {
          // For GBP, use the directly edited value
          update.subscriptions[currency] = parseFloat(tierData.subscriptions[currency]);
        } else {
          // For other currencies, calculate based on GBP and currency rates
          const gbpPrice = parseFloat(tierData.subscriptions.GBP);
          const rate = currencies[currency] / currencies.GBP;
          update.subscriptions[currency] = parseFloat((gbpPrice * rate).toFixed(2));
        }
      }
      
      updateOps.push(volumePricingContainer.items.upsert(update));
    }
    
    await Promise.all(updateOps);
    res.redirect("/admin?step=4&message=Volume pricing updated successfully");
  } catch (err) {
    console.error("Error updating volume pricing:", err);
    res.redirect("/admin?message=Error updating volume pricing");
  }
});

app.post("/admin/updateBasePrices", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { monthlySubscriptions = {} } = req.body;
    const processedAnnualSubscriptions = {};
    for (const [currency, monthlyPriceStr] of Object.entries(monthlySubscriptions)) {
        const monthlyPrice = parseFloat(monthlyPriceStr) || 0;
        const annualPrice = monthlyPrice * 12;
        processedAnnualSubscriptions[currency] = parseFloat(annualPrice.toFixed(2));
    }
    const update = {
      id: "BasePrices",
      userCount: null,
      volumeDiscount: null,
      subscriptions: processedAnnualSubscriptions
    };
    await volumePricingContainer.items.upsert(update);

    // Recalculate all volume tier prices using the NEW base prices
    await recalculateVolumePrices(processedAnnualSubscriptions); // Pass new base prices

    res.redirect("/admin?step=4&message=Base prices updated and volume tiers recalculated");
  } catch (err) {
    console.error("Error updating base prices:", err);
    res.redirect("/admin?message=Error updating base prices: " + err.message);
  }
});

async function recalculateVolumePrices(basePrices) {
  try {
    const { resources: tiers } = await volumePricingContainer.items
      .query({
        query: "SELECT * FROM c WHERE c.userCount != null ORDER BY c.userCount ASC"
      })
      .fetchAll();

    const updatePromises = tiers.map(tier => {
      const newSubscriptions = {};
      // --- Use the passed basePrices object ---
      for (const [currency, basePrice] of Object.entries(basePrices)) {
        // Apply formula: final price = (user count * base price) * (1 - volume discount)
        const calculatedPrice = (tier.userCount * basePrice) * (1 - tier.volumeDiscount);
        newSubscriptions[currency] = parseFloat(calculatedPrice.toFixed(2));
      }
      // --- End of using passed basePrices ---
      return volumePricingContainer.items.upsert({
        ...tier,
        subscriptions: newSubscriptions
      });
    });
    await Promise.all(updatePromises);
    console.log(`Successfully recalculated ${tiers.length} volume pricing tiers`);
  } catch (err) {
    console.error("Error recalculating volume prices:", err);
    throw err;
  }
}
app.post("/admin/addVolumeTier", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { userCount, volumeDiscount } = req.body;

    // Get base prices
    const { resources: basePricesDocs } = await volumePricingContainer.items
      .query({
        query: "SELECT * FROM c WHERE c.id = 'BasePrices'"
      })
      .fetchAll();
    if (!basePricesDocs.length) {
      throw new Error("Base prices not found");
    }
    const basePrices = basePricesDocs[0].subscriptions; // Get base prices object

    const discountValue = parseFloat(volumeDiscount) / 100;

    // Calculate prices for each currency using base prices
    const subscriptions = {};
    for (const [currency, basePrice] of Object.entries(basePrices)) {
      // Apply formula: final price = (user count * base price) * (1 - volume discount)
      const calculatedPrice = (userCount * basePrice) * (1 - discountValue);
      subscriptions[currency] = parseFloat(calculatedPrice.toFixed(2));
    }

    const newTier = {
      id: userCount.toString(),
      userCount: parseInt(userCount),
      volumeDiscount: discountValue,
      subscriptions
    };

    await volumePricingContainer.items.create(newTier);

    const { resources: updatedTiers } = await volumePricingContainer.items
      .query("SELECT * FROM c ORDER BY c.userCount ASC")
      .fetchAll();
    res.json({
      success: true,
      message: "New volume pricing tier added successfully",
      tiers: updatedTiers
    });
  } catch (err) {
    console.error("Error adding new volume tier:", err);
    res.status(500).json({
      success: false,
      message: "Error adding new volume pricing tier: " + err.message,
      details: err.message
    });
  }
});
// Updated delete endpoint with better error handling
app.post("/admin/deleteVolumeTier", async (req, res) => {
  const { tierId } = req.body;
  
  try {
    // First get the exact document to ensure we have correct types
    const { resources: tiers } = await volumePricingContainer.items
      .query({
        query: "SELECT * FROM c WHERE c.id = @id",
        parameters: [{ name: "@id", value: tierId }]
      })
      .fetchAll();

    if (!tiers || tiers.length === 0) {
      return res.status(404).json({ success: false, message: "Tier not found" });
    }

    const tier = tiers[0];
    
    // Delete using the correct types:
    // - id as string (tier.id)
    // - userCount as number (tier.userCount)
    await volumePricingContainer.item(tier.id, tier.userCount).delete();
    
    // Get updated list
    const { resources: updatedTiers } = await volumePricingContainer.items
      .query("SELECT * FROM c ORDER BY c.userCount ASC")
      .fetchAll();
    
    res.json({ success: true, tiers: updatedTiers });
    
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ 
      success: false,
      message: "Error deleting tier",
      details: err.message
    });
  }
});

// POST /submit-form
app.post("/submit-form", async (req, res) => {
  const {
    ordererName,
    ordererEmail,
    partnerCompany,
    partnerSignatory,
    partnerContactName,
    partnerContactPhone,
    partnerContactEmail,
    customerCompany,
    customerAddress,
    customerBusinessNumber,
    customerContactName,
    customerContactEmail,
    customerContactPhone,
    numUsers,
    customerPrice,
    startDate,
    initialTerm,
    tenantURL,
    currency
  } = req.body;
  try {
    // Fetch system email
    const { resources: emailDoc } = await customerContainer.items.query({
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: "sysemail" }]
    }).fetchAll();
    const sysemail = emailDoc[0]?.email || "";
    
    // Fetch field configurations
    const { resources: fieldConfigs } = await formConfigContainer.items.query({
      query: "SELECT * FROM c"
    }).fetchAll();
    const fieldConfigMap = {};
    fieldConfigs.forEach(config => {
      fieldConfigMap[config.fieldName] = config;
    });
    
    // Prepare DB item
    const item = {
      id: `${Date.now()}`,
      ordererName,
      ordererEmail,
      partnerCompany,
      partnerSignatory,
      partnerContactName,
      partnerContactPhone,
      partnerContactEmail,
      customerCompany,
      customerAddress,
      customerBusinessNumber,
      customerContactName,
      customerContactEmail,
      customerContactPhone,
      numUsers: Number(numUsers || 0),
      customerPrice: parseFloat(customerPrice || 0),
      currency,
      startDate,
      initialTerm,
      tenantURL,
      sysemail,
      submittedAt: new Date().toISOString()
    };
    
    // Save to Cosmos DB
    const { resource } = await customerContainer.items.create(item, {
      partitionKey: customerCompany
    });
    console.log("Inserted item into Cosmos DB:", resource);

    // --- Check if email client is available ---
    if (!emailClient) {
      console.error("Email client is not initialized. Cannot send submission confirmation.");
      // Still render success page even if email fails
      return res.render("thankyou", {
        ordererName,
        customerCompany,
        ordererEmail
      });
    }

    // --- Use Azure Communication Services Email ---
    const senderAddress = process.env.EMAIL_USER; // Assuming EMAIL_USER holds the verified ACS sender address
    if (!senderAddress) {
        throw new Error("EMAIL_USER (sender address) is not defined in environment variables for ACS.");
    }

    // Prepare email content
    const emailContent = `
        <h2>New Order Submitted</h2>
        <p><strong>${fieldConfigMap.ordererName?.title || 'Orderer'}:</strong> ${ordererName}</p>
        <p><strong>${fieldConfigMap.ordererEmail?.title || 'Orderer email'}:</strong> ${ordererEmail}</p>
        <p><strong>${fieldConfigMap.partnerCompany?.title || 'Partner Company'}:</strong> ${partnerCompany}</p>
        <p><strong>${fieldConfigMap.customerCompany?.title || 'Customer Company'}:</strong> ${customerCompany}</p>
        <p><strong>${fieldConfigMap.customerAddress?.title || 'Customer Address'}:</strong> ${customerAddress}</p>
        <p><strong>${fieldConfigMap.customerBusinessNumber?.title || 'Business Number'}:</strong> ${customerBusinessNumber}</p>
        <p><strong>${fieldConfigMap.customerContactName?.title || 'Contact Name'}:</strong> ${customerContactName}</p>
        <p><strong>${fieldConfigMap.customerContactEmail?.title || 'Contact Email'}:</strong> ${customerContactEmail}</p>
        <p><strong>${fieldConfigMap.numUsers?.title || 'Number of users'}:</strong> ${numUsers}</p>
        <p><strong>${fieldConfigMap.customerPrice?.title || 'Customer price'}:</strong> ${customerPrice}</p>
        <p><strong>${fieldConfigMap.currency?.title || 'Currency'}:</strong> ${currency}</p>
        <p><strong>${fieldConfigMap.startDate?.title || 'Start Date'}:</strong> ${startDate}</p>
        <p><strong>${fieldConfigMap.initialTerm?.title || 'Initial Term'}:</strong> ${initialTerm} months</p>
        <p><strong>${fieldConfigMap.tenantURL?.title || 'Tenant URL'}:</strong> ${tenantURL}</p>
        <hr />
        <p>This is an automated message.</p>
      `;

    const emailMessage = {
      senderAddress: senderAddress,
      recipients: {
        to: [
            { address: sysemail },     // System email
            { address: ordererEmail }  // Orderer email
        ],
      },
      content: {
        subject: `New Order Submission: ${customerCompany}`,
        html: emailContent, // Use HTML body
        // plainText: emailContent.replace(/<[^>]*>?/gm, '') // Optional: Generate plain text version
      },
    };

    // --- Updated to use the helper function ---
    const sendResult = await sendEmailWithACS(emailMessage);
    console.log("Submission confirmation email sent successfully. Operation ID:", sendResult.id);

    // --- End of ACS Email Usage ---

    res.render("thankyou", {
      ordererName,
      customerCompany,
      ordererEmail
    });
  } catch (err) {
    console.error("Error saving to DB or sending email:", err.message);
    // Differentiate between ACS errors and others if needed
    if (err.name === 'RestError') {
        console.error("ACS Email Error Details:", err);
    }
    res.status(500).send("Failed to process your request.");
  }
});

// POST /deleteCustomer
app.post("/deleteCustomer", async (req, res) => {
  const { id, customerCompany } = req.body;

  if (!id || !customerCompany) {
    return res.status(400).send("Missing id or customerCompany");
  }

  try {

    console.log("Deleting customer with id:", id, "and partitionKey:", customerCompany);
    await customerContainer.item(id, customerCompany).delete();
    res.redirect("/orderAdmin");
  } catch (err) {
    console.error("Error deleting customer:", err.message);
    res.status(500).send("Failed to delete customer");
  }
});

// POST /calculate
app.post("/calculate", async (req, res) => {
    // Extract form data
    const { amount, currency, commitmentDiscount, isCurrentSubscriber, promoCode } = req.body;
    const numSubscribers = Number(amount);

    // Input validation
    if (isNaN(numSubscribers) || numSubscribers <= 0) {
        return res.status(400).send("Invalid number of subscribers.");
    }
    if (!currency) {
        return res.status(400).send("Currency is required.");
    }

    try {
        // --- Fetch Discount Rules ---
        const { resource: discountDoc } = await discountContainer.item("discount-rules", "rules").read();
        if (!discountDoc) {
            return res.status(500).send("Discount rules not found.");
        }

        // --- Determine Discount Decimals ---

        // 1. Subscriber Discount (e.g., Partner/Current Customer)
        // - Modified: Use the new structure for the additional discount -
        let subscriberDiscountDecimal = 0; // Default value
        if (isCurrentSubscriber === "on") { // Checkbox is checked
            if (discountDoc.additionalDiscount) {
                // If new structure exists, use it
                subscriberDiscountDecimal = discountDoc.additionalDiscount.additionalDiscountAmount || 0;
            } else if (discountDoc.currentSubscriber !== undefined) {
                // Fallback: If old structure exists, use it
                subscriberDiscountDecimal = discountDoc.currentSubscriber || 0;
            }
        }
        // - End Modification -

        // 2. Promo Code Discount (Validate internally)
        let promoDiscountDecimal = 0;
        let promoDescription = "";
        if (promoCode && promoCode.trim()) {
            try {
                const trimmedCode = promoCode.trim();
                const now = new Date().toISOString();

                // Query for the code, ensuring it's active and within validity period
                const querySpec = {
                    query: `
                        SELECT *
                        FROM c
                        WHERE c.code = @code
                        AND c.isActive = true
                        AND (NOT IS_DEFINED(c.startDate) OR c.startDate <= @now)
                        AND (NOT IS_DEFINED(c.endDate) OR c.endDate >= @now)
                    `,
                    parameters: [
                        { name: "@code", value: trimmedCode },
                        { name: "@now", value: now }
                    ]
                };

                const { resources } = await promoCodesContainer.items.query(querySpec).fetchAll();

                if (resources.length > 0) {
                    const promo = resources[0];
                    promoDiscountDecimal = (parseFloat(promo.discountPercentage) || 0) / 100;
                    promoDescription = promo.description || "";
                    console.log("Valid promo code applied:", trimmedCode, "Discount:", promoDiscountDecimal);
                } else {
                    console.log("Invalid or expired promo code provided:", trimmedCode);
                    // Optionally add a message to be passed to the result page
                    // res.locals.promoMessage = "Invalid or expired promo code.";
                }
            } catch (err) {
                console.error("Error validating promo code internally:", err);
                // Handle error, maybe log, but don't crash calculation
            }
        }

        // --- Fetch Pricing Data (PPU or Volume) ---
        let ppuValueRaw = 0;
        let usedVolumePricing = false;
        let volumeBasePrice = 0;

        if (numSubscribers >= 1000) {
            // --- Volume Pricing Calculation ---
            try {
                const { resources: tiers } = await volumePricingContainer.items.query({
                    query: "SELECT * FROM c WHERE c.userCount != null ORDER BY c.userCount ASC"
                }).fetchAll();

                // Find the appropriate tier
                let selectedTier = tiers[tiers.length - 1]; // Default to last (highest) tier
                for (const tier of tiers) {
                    if (numSubscribers <= tier.userCount) {
                        selectedTier = tier;
                        break;
                    }
                }

                if (selectedTier && selectedTier.subscriptions && selectedTier.subscriptions[currency] !== undefined) {
                     volumeBasePrice = selectedTier.subscriptions[currency];
                     usedVolumePricing = true;
                } else {
                     console.warn(`Volume price for ${numSubscribers} users and currency ${currency} not found. Defaulting to PPU logic.`);
                     // Fall back to PPU logic if volume price is missing
                }
            } catch (volumeErr) {
                console.error("Error fetching volume pricing ", volumeErr);
                // Fall back to PPU logic on error
            }
            // --- End Volume Pricing Calculation ---
        }

        // --- PPU Logic (if not using Volume or Volume failed) ---
        if (!usedVolumePricing) {
            let ppuDoc = null;
            try {
                // 1. Attempt to fetch the latest PPU data
                const { resources: ppuDocs } = await ppusContainer.items
                    .query("SELECT * FROM c ORDER BY c.date DESC")
                    .fetchAll();

                if (ppuDocs && ppuDocs.length > 0) {
                    // a. Use the most recent PPU document found
                    ppuDoc = ppuDocs[0];
                    console.log("PPU data found:", ppuDoc.id);
                } else {
                    // b. No PPU data found, create default
                    console.log("No PPU data found. Creating default PPU document...");
                    const defaultPPUData = {
                        // Generate a unique ID based on date and timestamp
                        id: `ppu-${new Date().toISOString().split('T')[0]}-${Date.now()}`,
                        date: new Date().toISOString(),
                        ppu: {
                            GBP: {
                                standard: 2.75
                            },
                            EUR: {
                                standard: 3.10
                            },
                            USD: {
                                standard: 3.30
                            }
                            // Add more currencies and values as needed for your defaults
                        }
                        // Note: _rid, _self, _etag, _attachments, _ts are generated by Cosmos DB
                        // Partition key (e.g., if path is '/PPUkey') should match the logic.
                        // If the partition key is simply the 'id' or derived from it, this might be sufficient.
                        // Adjust PPUkey assignment if your container requires a specific partition key value.
                        // Example if PPUkey is a separate field and the partition key path is '/PPUkey':
                        // PPUkey: `ppu-${new Date().toISOString().split('T')[0]}-${Date.now()}` // Or a fixed value if that's the design
                    };

                    // --- Important: Ensure Partition Key is Correct ---
                    // If your PPUs container has a partition key path like '/PPUkey',
                    // and it's not simply derived from 'id', you might need to set it explicitly.
                    // Cosmos DB SDK often infers it, but being explicit is safer.
                    // Assuming partition key path is '/PPUkey' and it should match the 'id' or part of it:
                    defaultPPUData.PPUkey = defaultPPUData.id; // Adjust this line based on your actual partition key logic

                    try {
                        // Create the default PPU document in the database
                        // Pass the partition key explicitly if required by your SDK version or setup
                        const { resource: createdDoc } = await ppusContainer.items.create(defaultPPUData, { partitionKey: defaultPPUData.PPUkey });
                        console.log("Default PPU document created successfully:", createdDoc.id);
                        ppuDoc = createdDoc; // Use the newly created document
                    } catch (createErr) {
                        console.error("Error creating default PPU document:", createErr);
                        // Depending on requirements, you might want to throw an error or proceed with ppuValueRaw = 0
                        // For now, we'll log the error and continue with default ppuValueRaw (0)
                        // Optionally, you could set a flag or message to indicate the default creation issue
                         return res.status(500).send("Failed to initialize pricing data.");
                    }
                }
            } catch (fetchErr) {
                console.error("Error fetching PPU ", fetchErr);
                // Handle error fetching PPU data, potentially defaulting or showing an error
                // For now, proceed with ppuDoc = null, leading to ppuValueRaw = 0
                 return res.status(500).send("Error retrieving pricing data.");
            }

            // 2. Determine ppuValueRaw using the fetched or created document
            if (ppuDoc?.ppu?.[currency]?.standard !== undefined) {
                ppuValueRaw = ppuDoc.ppu[currency].standard;
            } else {
                // This case handles:
                // - No PPU doc found or created
                // - PPU doc found/created but missing the specific currency or 'standard' tier
                console.warn(`PPU value for currency '${currency}' (standard tier) not found in document (or no document). Defaulting to 0.`);
                // ppuValueRaw remains 0
                // Consider if you want to use a hardcoded default here if the specific currency isn't found
                // even if a PPU doc exists. Or, you might want to show an error if *no* PPU doc could be sourced.
                 // Optionally return an error if critical pricing is missing
                 // return res.status(500).send(`Pricing data for currency ${currency} is unavailable.`);
            }
        }
        // --- End PPU Logic ---

        const ppuValue = Number(ppuValueRaw);
        if (isNaN(ppuValue)) {
            console.warn(`ppuValueRaw '${ppuValueRaw}' could not be converted to a valid number for currency ${currency}. Defaulting to 0.`);
            // ppuValue will be 0 due to Number conversion of non-numeric ppuValueRaw or 0 itself
        }

        // --- CALCULATE PRICES WITH MULTIPLICATIVE DISCOUNTS ---
        // Define available commitment options based on discount rules
        const commitmentOptions = Object.entries(discountDoc.commitments || {}).map(([key, value]) => ({
             label: key.replace('_', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase()),
             value: value, // Value is already decimal from DB
             key: key
        }));

        const allPrices = commitmentOptions.map(option => {
            const commitmentDiscountDecimal = option.value; // e.g., 0.15 for 15%

            // - KEY CHANGE: Apply discounts multiplicatively -
            // Formula: Final Multiplier = (1 - D_subscriber) * (1 - D_promo) * (1 - D_commitment)
            const combinedDiscountMultiplier =
                (1 - subscriberDiscountDecimal) * // Use the potentially migrated or new value
                (1 - promoDiscountDecimal) *
                (1 - commitmentDiscountDecimal);

            let annualPrice, monthlyPrice, pricePerUser;

            if (usedVolumePricing) {
                // - Volume Pricing Calculation -
                pricePerUser = volumeBasePrice * combinedDiscountMultiplier;
                annualPrice = pricePerUser * numSubscribers; // Assuming volume base price is annual
                monthlyPrice = annualPrice / 12;
                // - End Volume Pricing Calculation -
            } else {
                // - PPU Pricing Calculation -
                pricePerUser = ppuValue * combinedDiscountMultiplier;
                annualPrice = pricePerUser * numSubscribers * 12;
                monthlyPrice = pricePerUser * numSubscribers;
                // - End PPU Pricing Calculation -
            }

            // Format prices to 2 decimal places for display
            annualPrice = parseFloat(annualPrice.toFixed(2));
            monthlyPrice = parseFloat(monthlyPrice.toFixed(2));
            pricePerUser = parseFloat(pricePerUser.toFixed(2));

            return {
                ...option,
                annualPrice,
                monthlyPrice,
                pricePerUser,
                isSelected: option.key === commitmentDiscount // Mark selected option
            };
        });

        const selectedOption = allPrices.find(p => p.isSelected) || allPrices[0];

        // - Modified: Pass the title to the result view -
        let additionalDiscountTitle = "Eligible for discount?"; // Default title
        if (discountDoc.additionalDiscount) {
            additionalDiscountTitle = discountDoc.additionalDiscount.Title || "Eligible for discount?";
        } else if (discountDoc.currentSubscriber !== undefined) {
            // Keep default title for migrated data unless you want to migrate the title too
        }
        // - End Modification -

        // Render the result page, passing the calculated data
        res.render("result", {
            amount: numSubscribers,
            currency: currency,
            allPrices: allPrices, // <-- This line passes the allPrices array
            selectedOption: selectedOption, // <-- And this passes the selected option

            // - Modified: Pass the discount title and value for display -
            // subscriberDiscount was calculated as a decimal, convert for display
            subscriberDiscount: Number((subscriberDiscountDecimal * 100).toFixed(2)),
            subscriberDiscountTitle: additionalDiscountTitle, // Pass the title
            // -
            // promoDiscount was calculated as a decimal, convert for display
            promoDiscount: Number((promoDiscountDecimal * 100).toFixed(2)),
            promoDescription: promoDescription,
            pricePerUser: selectedOption.pricePerUser,
            monthlyPrice: selectedOption.monthlyPrice,
            annualPrice: selectedOption.annualPrice,
            commitmentLabel: selectedOption.label,
            QuotePrice: { // Pass the full price object for saving
                pricePerUser: selectedOption.pricePerUser,
                monthlyPrice: selectedOption.monthlyPrice,
                annualPrice: selectedOption.annualPrice
            }
        });

    } catch (err) {
        console.error("Error during calculation:", err);
        res.status(500).send("An error occurred during the calculation. Please try again.");
    }
});




// POST /save-quote
// This route handles saving the quote data sent from result.ejs
app.post("/save-quote", async (req, res) => {
    // Note: QuotePrice is now an object, not a string
    const { QuoteCustomerName, QuotePrice, QuoteUserAmount, QuoteCurrency, QuoteCustomerEmail } = req.body;
    try {
        // 1. Basic validation
        if (!QuoteCustomerName || !QuotePrice || !QuoteUserAmount || !QuoteCurrency || !QuoteCustomerEmail) {
            return res.status(400).json({
                message: "Missing required fields (Name, Price, Amount, Currency, Email)."
            });
        }
        
        // 2. Generate a random ID (e.g., 9-digit number)
        const quoteId = Math.floor(Math.random() * 900000000) + 100000000; // Between 100000000 and 999999999
        
        // 3. Get the Quotes container
        const quotesContainer = customerDatabase.container("Quotes");
        
        // 4. Construct the quote object (including the email)
        const quoteToSave = {
            id: quoteId.toString(), // Ensure ID is a string as Cosmos DB expects
            QuoteCustomerName: QuoteCustomerName,
            QuotePrice: QuotePrice, // Now an object with all commitment prices
            QuoteUserAmount: QuoteUserAmount, // Already formatted as string from client
            QuoteCurrency: QuoteCurrency,
            QuoteCustomerEmail: QuoteCustomerEmail // Add the email to the saved data
        };
        
        // 5. Save the quote to Cosmos DB
        const { resource: savedQuote } = await quotesContainer.items.upsert(quoteToSave);
        console.log(`Quote saved successfully with ID: ${savedQuote.id}`);

        // --- Check if email client is available ---
        if (!emailClient) {
            console.error("Email client is not initialized. Cannot send quote email.");
            // Still return success for quote saving even if email fails
            return res.status(201).json({
                message: "Quote saved successfully, but email could not be sent.",
                quoteId: savedQuote.id
            });
        }

        // --- Use Azure Communication Services Email ---
        const senderAddress = process.env.EMAIL_USER; // Assuming EMAIL_USER holds the verified ACS sender address
        if (!senderAddress) {
            throw new Error("EMAIL_USER (sender address) is not defined in environment variables for ACS.");
        }

        // Create plan description for email
        let planDescriptionHTML = "<p><strong>Available Plans:</strong></p><ul>";
        if (QuotePrice && typeof QuotePrice === 'object') {
            // Create a readable description of all plans
            for (const [term, price] of Object.entries(QuotePrice)) {
                planDescriptionHTML += `<li>${term}: <strong>${parseFloat(price).toFixed(2)} ${QuoteCurrency}</strong></li>`;
            }
        } else {
             planDescriptionHTML += `<li>Custom Plan: <strong>${QuotePrice} ${QuoteCurrency}</strong></li>`;
        }
        planDescriptionHTML += "</ul>";

        const emailContent = `
                <h2>Subscription Quote</h2>
                <p>Thank you for your interest in our services.</p>
                <p><strong>Quote ID:</strong> ${quoteId}</p>
                <p><strong>Customer Name:</strong> ${QuoteCustomerName}</p>
                ${planDescriptionHTML}
                <p><strong>Number of Users:</strong> ${QuoteUserAmount}</p>
                <p><strong>Currency:</strong> ${QuoteCurrency}</p>
                <hr />
                <p>This is an automated message containing your saved quote.</p>
            `;

        const emailMessage = {
          senderAddress: senderAddress,
          recipients: {
            to: [{ address: QuoteCustomerEmail }], // Send to the customer's email
          },
          content: {
            subject: `Your Subscription Quote #${quoteId}`,
            html: emailContent, // Use HTML body
            // plainText: emailContent.replace(/<[^>]*>?/gm, '') // Optional: Generate plain text version
          },
        };

        // --- Updated to use the helper function ---
        const sendResult = await sendEmailWithACS(emailMessage);
        console.log(`Quote email sent successfully to ${QuoteCustomerEmail}. Operation ID:`, sendResult.id);

        // --- End of ACS Email Usage ---

        // 7. Send success response with the ID
        res.status(201).json({
            message: "Quote saved and email sent successfully.",
            quoteId: savedQuote.id
        });
    } catch (err) {
        console.error("Error saving quote or sending email:", err.message);
        // Differentiate between ACS errors and others if needed
        if (err.name === 'RestError') {
            console.error("ACS Email Error Details:", err);
        }
        // Send error response
        res.status(500).json({
            message: "Failed to save quote or send email. Please try again later."
        });
    }
});

app.post("/admin/createPromoCode", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { code, discountPercentage, description, validFrom, validTo } = req.body;

    if (!code || discountPercentage === undefined || discountPercentage < 0 || discountPercentage > 100) {
      return res.status(400).json({ success: false, message: "Invalid promo code data." });
    }

    const newPromoCode = {
      id: uuidv4(), // Unique ID for the document
      code: code.trim(), // Ensure code is trimmed
      discountPercentage: parseFloat(discountPercentage),
      description: description || "",
      validFrom: validFrom ? new Date(validFrom).toISOString() : new Date().toISOString(),
      validTo: validTo ? new Date(validTo).toISOString() : null, // null means no expiry date set
      isActive: true, // Default to active
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Check for duplicate code (optional but recommended)
    const { resources: existingCodes } = await promoCodesContainer.items
      .query({
        query: "SELECT * FROM c WHERE c.code = @code",
        parameters: [{ name: "@code", value: newPromoCode.code }]
      })
      .fetchAll();

    if (existingCodes.length > 0) {
       return res.status(400).json({ success: false, message: "Promo code already exists." });
    }

    await promoCodesContainer.items.create(newPromoCode);

    res.json({ success: true, message: "Promo code created successfully.", promoCode: newPromoCode });
  } catch (err) {
    console.error("Error creating promo code:", err);
    res.status(500).json({ success: false, message: "Error creating promo code." });
  }
});

app.get("/admin/promo-codes", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { resources: promoCodes } = await promoCodesContainer.items.query({
      query: "SELECT * FROM c ORDER BY c.createdAt DESC"
    }).fetchAll();

    // --- Add logic to determine effective status ---
    const now = new Date().toISOString();
    const promoCodesWithEffectiveStatus = promoCodes.map(code => {
      let isEffectivelyActive = code.isActive; // Start with the stored isActive flag

      // Check if the code is within the valid date range
      if (isEffectivelyActive) { // Only check dates if it's flagged as active
        if (code.validFrom && code.validFrom > now) {
          isEffectivelyActive = false; // Not yet valid
        } else if (code.validTo && code.validTo < now) {
          isEffectivelyActive = false; // Expired
        }
      }

      // Add the effective status to the object
      return {
        ...code,
        isEffectivelyActive: isEffectivelyActive
      };
    });
    // --- End of logic ---

    // Send the modified list with effective status
    res.json({ success: true, promoCodes: promoCodesWithEffectiveStatus });
  } catch (err) {
    console.error("Error fetching promo codes:", err);
    res.status(500).json({ success: false, message: "Error fetching promo codes." });
  }
});

app.put("/admin/promo-codes/:id", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const promoCodeId = req.params.id;
    const updateData = req.body; // e.g., { isActive: false, description: "Updated desc" }

    // Fetch existing promo code
     const { resource: existingCode } = await promoCodesContainer.item(promoCodeId, promoCodeId).read();
     if (!existingCode) {
        return res.status(404).json({ success: false, message: "Promo code not found." });
     }

     // Prepare update object
     const updatedCode = {
        ...existingCode,
        ...updateData, // Overwrite fields provided in the request body
        updatedAt: new Date().toISOString()
     };

     await promoCodesContainer.item(promoCodeId, promoCodeId).replace(updatedCode);
     res.json({ success: true, message: "Promo code updated.", promoCode: updatedCode });

  } catch (err) {
    console.error("Error updating promo code:", err);
    res.status(500).json({ success: false, message: "Error updating promo code." });
  }
});

app.delete("/admin/promo-codes/:id", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const promoCodeId = req.params.id;
    await promoCodesContainer.item(promoCodeId, promoCodeId).delete();
    res.json({ success: true, message: "Promo code deleted." });
  } catch (err) {
    console.error("Error deleting promo code:", err);
    if (err.code === 404) {
       res.status(404).json({ success: false, message: "Promo code not found." });
    } else {
       res.status(500).json({ success: false, message: "Error deleting promo code." });
    }
  }
});

app.post("/api/validate-promo-code", async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ isValid: false, message: "Promo code is required." });
    }

    const now = new Date().toISOString();

    // Query for the code, ensuring it's active and within validity period
    const { resources: promoCodes } = await promoCodesContainer.items
      .query({
        query: `SELECT * FROM c
                WHERE c.code = @code
                AND c.isActive = true
                AND (NOT IS_DEFINED(c.validFrom) OR c.validFrom <= @now)
                AND (NOT IS_DEFINED(c.validTo) OR c.validTo >= @now)`,
        parameters: [
          { name: "@code", value: code.trim() },
          { name: "@now", value: now }
        ]
      })
      .fetchAll();

    const promoCode = promoCodes[0];

    if (promoCode) {
      res.json({
        isValid: true,
        discountPercentage: promoCode.discountPercentage,
        description: promoCode.description
      });
    } else {
      res.json({ isValid: false, message: "Invalid or expired promo code." });
    }
  } catch (err) {
    console.error("Error validating promo code:", err);
    res.status(500).json({ isValid: false, message: "Error validating promo code." });
  }
});



app.get("/stylesAdmin", /*requireOrderAdminOTP*/ async (req, res) => { // Use requireOrderAdminOTP for security
    try {
        // Fetch current styles from Cosmos DB
        const { resource: styles } = await siteStylesContainer.item("site-styles", "config").read(); // Use a fixed id/partition key

        res.render("stylesAdmin", {
            styles: styles || {}, // Pass styles object, default to empty if not found
            message: req.query.message || null // For success/error messages
        });
    } catch (err) {
        console.error("Error fetching site styles:", err);
        // Render page with defaults if fetch fails
        res.render("stylesAdmin", {
            styles: {},
            message: "Error loading styles. Showing defaults."
        });
    }
});

app.post("/stylesAdmin", /*requireOrderAdminOTP*/ async (req, res) => {
    try {
        // Ensure the partition key property name matches your container definition
        // If partition key path is '/config', use 'config' here:
        const stylesToSave = {
            id: "site-styles",
            config: "config", // <-- Corrected partition key property and value
            // Map request body to style object
            primaryColor: req.body.primaryColor,
            primaryHoverColor: req.body.primaryHoverColor,
            secondaryColor: req.body.secondaryColor,
            secondaryTextColor: req.body.secondaryTextColor,
            secondaryHoverColor: req.body.secondaryHoverColor,
            backgroundColor: req.body.backgroundColor,
            containerColor: req.body.containerColor,
            textColor: req.body.textColor,
            linkColor: req.body.linkColor,
            linkHoverColor: req.body.linkHoverColor,
            infoIconColor: req.body.infoIconColor,
            infoIconHoverColor: req.body.infoIconHoverColor
            // Add other colors as needed
        };

        // Upsert the styles document
        // Make sure to pass the partition key value correctly in the options if needed by the SDK version
        // Often, the SDK can infer it from the item object, but explicitly passing it can prevent issues.
        await siteStylesContainer.items.upsert(stylesToSave, { partitionKey: stylesToSave.config }); // Explicitly pass partition key

        res.redirect("/stylesAdmin?message=Styles updated successfully!");
    } catch (err) {
        console.error("Error saving site styles:", err);
        res.redirect("/stylesAdmin?message=Error saving styles.");
    }
});

app.get("/api/site-styles", async (req, res) => {
    try {
        const { resource: styles } = await siteStylesContainer.item("site-styles", "config").read();
        if (styles) {
            // Return only the color properties, excluding metadata
            const { id, type, _rid, _self, _etag, _attachments, _ts, ...colorStyles } = styles;
            res.json(colorStyles);
        } else {
            res.status(404).json({ message: "Styles not found" }); // Or return defaults
        }
    } catch (err) {
        console.error("Error fetching site styles API:", err);
        // Return empty object or defaults on error to prevent frontend breakage
        res.status(500).json({});
    }
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Calculator app listening on port ${port}`);
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});
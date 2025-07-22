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

// Enable .env support (for local development)
dotenvConfig();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

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

// GET /verify-email – page where admin inputs email
app.get('/verify-email', (req, res) => {
  res.render('verifyEmail', { error: null });
});

app.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  try {
    const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

    if (!config.adminEmails.includes(email)) {
      return res.render('verifyEmail', { error: "Email not authorized." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    req.session.otp = otp;
    req.session.otpEmail = email;
    req.session.otpExpires = Date.now() + 15 * 60 * 1000; //aika

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your One-Time Passcode (OTP)",
      text: `Your OTP is: ${otp}`
    });

    res.render('enterOtp', { email, error: null });
  } catch (err) {
    console.error("Error sending OTP:", err.message);
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
    const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();

    if (!config.adminEmails.includes(email)) {
      return res.render('login', { error: "Email not authorized." });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store code in session
    req.session.resetCode = code;
    req.session.resetEmail = email;
    req.session.codeExpires = Date.now() + 15 * 60 * 1000; // 10 min expiry

    // Send email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Admin Reset Code",
      text: `Your code is: ${code}`
    });

    res.render('resetPassword', { email, error: null });
  } catch (err) {
    console.error("Reset code error:", err);
    res.render('login', { error: "Failed to send reset code." });
  }
});

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

const calcDatabase = cosmosClient.database("CalculatorConfigDB");
const calcContainer = calcDatabase.container("Variables");

const customerDatabase = cosmosClient.database("CustomerInfo");
const customerContainer = customerDatabase.container("CustomerInfo");

const adminConfigContainer=customerDatabase.container("adminConfig");

const formConfigContainer = customerDatabase.container("FormConfig");

// GET /initFormConfig - Initialize form configurations with defaults
app.get("/initFormConfig", requireOrderAdminOTP, async (req, res) => {
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
app.get("/formConfig", requireOrderAdminOTP, async (req, res) => {
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
app.post("/updateFormConfig", requireOrderAdminOTP, async (req, res) => {
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
      customerContactName: quote.QuoteCustomerName || '',
      numUsers: quote.QuoteUserAmount || '',
      currency: quote.QuoteCurrency || '',
      customerPrice: quote.QuotePrice || ''
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
app.get("/calculator", (req, res) => {
  res.render("calculator");
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
app.get("/orderAdmin", requireOrderAdminOTP, async (req, res) => {
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
app.post("/updateTooltips", requireOrderAdminOTP, async (req, res) => {
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

//GET /admin
app.get("/admin", async (req, res) => {
  try {
    console.log("Attempting to fetch variables from Cosmos DB...");
    
    const querySpec = {
      query: "SELECT c.id, c.variableName, c.Amount FROM c"
    };
    
    console.log("Executing query:", querySpec.query);
    
    const { resources: variables, diagnostics } = await calcContainer.items
      .query(querySpec)
      .fetchAll();
    
    console.log("Query diagnostics:", diagnostics);
    console.log("Retrieved variables:", JSON.stringify(variables, null, 2));
    
    if (!variables || variables.length === 0) {
      console.warn("No variables found in the database");
      return res.render("admin", {
        variables: [],
        message: "No variables found in the database"
      });
    }

    res.render("admin", { 
      variables: variables,
      message: null 
    });
  } catch (err) {
    console.error("Detailed error fetching variables:", {
      message: err.message,
      code: err.code,
      stack: err.stack,
      endpoint: endpoint,
      database: "CalculatorConfigDB",
      container: "Variables"
    });
    res.status(500).render("admin", {
      variables: [],
      message: "Error loading variables - check server logs"
    });
  }
});

// POST /admin/update - save updated variables
app.post("/admin/update", async (req, res) => {
  try {
    console.log("Received update request:", req.body);

    // Handle both single and array inputs
    const ids = Array.isArray(req.body.id) ? req.body.id : [req.body.id];
    const variableNames = Array.isArray(req.body.variableName) ? req.body.variableName : [req.body.variableName];
    const amounts = Array.isArray(req.body.Amount) ? req.body.Amount : [req.body.Amount];

    // Validate input arrays
    if (ids.length !== variableNames.length || ids.length !== amounts.length) {
      throw new Error("Mismatched input array lengths");
    }

    const updatedVariables = [];

    for (let i = 0; i < ids.length; i++) {
      const id = ids[i];
      const variableName = variableNames[i];
      const amount = parseFloat(amounts[i]); // Ensure numeric value

      // Validate inputs
      if (!id || !variableName || isNaN(amount)) {
        console.warn(`Skipping invalid input at index ${i}:`, { id, variableName, amount });
        continue;
      }

      try {
        // Read the existing item using variableName as partitionKey
        const { resource: item } = await calcContainer.item(id, variableName).read();

        if (!item) {
          throw new Error(`Item not found with id: ${id} and variableName: ${variableName}`);
        }

        // Update the item
        item.Amount = amount;
        item.value = amount; // Update both fields if needed

        // Replace the item
        await calcContainer.item(id, variableName).replace(item);
        updatedVariables.push({ id, variableName, amount });

        console.log(`Successfully updated item: ${id} (${variableName}) with amount: ${amount}`);
      } catch (err) {
        console.error(`Error updating item ${id} (${variableName}):`, err.message);
        throw err; // Re-throw to catch in outer try-catch
      }
    }

    // Fetch updated variables to show in response
    const { resources: variables } = await calcContainer.items.query({
      query: "SELECT c.id, c.variableName, c.Amount FROM c"
    }).fetchAll();

    res.render("admin", {
      variables: variables,
      message: `Successfully updated ${updatedVariables.length} variable(s)`
    });

  } catch (err) {
    console.error("Failed to update variables:", {
      error: err.message,
      stack: err.stack,
      requestBody: req.body
    });
    
    // Try to get current variables even if update failed
    let variables = [];
    try {
      const result = await calcContainer.items.query({
        query: "SELECT c.id, c.variableName, c.Amount FROM c"
      }).fetchAll();
      variables = result.resources;
    } catch (fetchErr) {
      console.error("Failed to fetch variables after update error:", fetchErr.message);
    }

    res.status(500).render("admin", {
      variables: variables,
      message: `Update failed: ${err.message}`
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

    // Send email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: [sysemail, ordererEmail],
      subject: `New Order Submission: ${customerCompany}`,
      html: `
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
      `
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");

    res.render("thankyou", {
      ordererName,
      customerCompany,
      ordererEmail
    });

  } catch (err) {
    console.error("Error saving to DB or sending email:", err.message);
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
  const { price, amount} = req.body;

  let multi = 0;
  try {
    // id = "VAR", partitionKey = "Sale2" (change as needed)
    const { resource: doc } = await calcContainer.item("Discount", "Commitment").read();
    multi = doc?.Amount ?? 0;
  } catch (err) {
    console.warn("Failed to fetch discount from Cosmos DB:", err.message);
  }

  // Calculate the multiplied amount
  const multipliedAmount =Number(amount*price)- Number(amount*price) * multi/100;

  // Render the result page with the calculation and submitted info
    res.render("result", {
    price,
    amount,
    multi,
    multipliedAmount
  });
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
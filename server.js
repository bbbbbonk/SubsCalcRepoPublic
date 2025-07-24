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
const discountContainer = calcDatabase.container("Discounts");
const volumePricingContainer = calcDatabase.container("VolumePricing");
const ppusContainer = calcDatabase.container("PPUs");
const currenciesContainer = calcDatabase.container("ExchangeRate");

const customerDatabase = cosmosClient.database("CustomerInfo");
const customerContainer = customerDatabase.container("CustomerInfo");

const adminConfigContainer=customerDatabase.container("adminConfig");
const formConfigContainer = customerDatabase.container("FormConfig");

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
app.get("/calculator", async (req, res) => {
  try {
    const { resource: discountDoc } = await discountContainer
      .item("discount-rules", "rules") // item(id, partitionKey)
      .read();

    if (!discountDoc || !discountDoc.commitments) {
      throw new Error("Discount document or commitments field not found");
    }

    const commitmentOptions = Object.entries(discountDoc.commitments).map(([key, value]) => ({
      label: key.replace('_', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase()), // "1_year" → "1 Year"
      value: value * 100,
      key: key
    }));

    const currentSubscriberDiscount = (discountDoc.currentSubscriber || 0) * 100;

    res.render("calculator", {
      commitmentOptions,
      currentSubscriberDiscount
    });
  } catch (err) {
    console.error("Failed to load discount options:", err.message);
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
      currenciesResponse
    ] = await Promise.all([
      discountContainer.item("discount-rules", "rules").read(),
      ppusContainer.items.query("SELECT * FROM c ORDER BY c.date DESC").fetchAll(),
      volumePricingContainer.items.query("SELECT * FROM c ORDER BY c.userCount ASC").fetchAll(),
      currenciesContainer.items.query("SELECT TOP 1 * FROM c ORDER BY c._ts DESC").fetchAll()
    ]);

    // Process discount rules
    const discountRules = discountRulesResponse.resource || {};
    if (discountRules.commitments) {
      discountRules.commitments = Object.entries(discountRules.commitments).map(([key, value]) => ({
        key,
        name: key.replace('_', ' ').replace(/(^\w|\s\w)/g, m => m.toUpperCase()),
        value: parseFloat(value) || 0
      }));
    }

    // Process PPUs (take the latest)
    const ppus = ppusResponse.resources[0]?.ppu || {};
    
    // Ensure all standard/alternate values are numbers
    for (const currency in ppus) {
      if (ppus[currency]) {
        ppus[currency].standard = Number(ppus[currency].standard) || 0;
        if (ppus[currency].alternate) {
          ppus[currency].alternate = Number(ppus[currency].alternate) || 0;
        }
      }
    }
    
    // Process volume pricing
    const volumePricing = volumePricingResponse.resources || [];

    // Process currencies - GBP is the base currency but editable
    const currenciesDoc = currenciesResponse.resources[0];
    let currencies = {
      GBP: 1.0 // Default base value
    };

    // If we have existing rates, use them
    if (currenciesDoc?.rates) {
      currencies = {
        GBP: parseFloat(currenciesDoc.rates.GBP) || 1.0,
        USD: parseFloat(currenciesDoc.rates.USD) || 1.3,
        EUR: parseFloat(currenciesDoc.rates.EUR) || 1.15
      };
    } else {
      // Default rates if none exist
      currencies = {
        GBP: 1.0,
        USD: 1.3,
        EUR: 1.15
      };
    }

    // Calculate derived rates based on GBP
    const derivedRates = {
      GBP: currencies.GBP,
      USD: currencies.USD / currencies.GBP, // Shows how many USD per GBP
      EUR: currencies.EUR / currencies.GBP  // Shows how many EUR per GBP
    };

    res.render("admin", {
      discountRules: discountRules || {
        commitments: [],
        currentSubscriber: 0
      },
      ppus: ppus || {},
      volumePricing: volumePricing || [],
      currencies: derivedRates, // Send derived rates to view
      rawCurrencies: currencies, // Send raw values for calculations
      message: req.query.message || null,
      baseCurrency: 'GBP'
    });

  } catch (err) {
    console.error("Error loading admin data:", err);
    res.status(500).render("admin", {
      discountRules: {
        commitments: [],
        currentSubscriber: 0
      },
      ppus: {},
      volumePricing: [],
      currencies: {
        GBP: 1.0,
        USD: 1.3,
        EUR: 1.15
      },
      rawCurrencies: {
        GBP: 1.0,
        USD: 1.3,
        EUR: 1.15
      },
      message: "Error loading configuration data",
      baseCurrency: 'GBP'
    });
  }
});

// POST /admin/update - save updated variables
app.post("/admin/updateDiscounts", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { commitments, currentSubscriber } = req.body;
    
    // Convert commitments from form data to object
    const commitmentsObj = {};
    for (const [key, value] of Object.entries(commitments)) {
      commitmentsObj[key] = parseFloat(value) / 100;
    }

    const update = {
      id: "discount-rules",
      rules: "rules", // partition key
      commitments: commitmentsObj,
      currentSubscriber: parseFloat(currentSubscriber) / 100
    };

    await discountContainer.items.upsert(update);
    res.redirect("/admin?message=Discounts updated successfully");
  } catch (err) {
    console.error("Error updating discounts:", err);
    res.redirect("/admin?message=Error updating discounts");
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

    res.redirect("/admin?message=PPUs updated successfully");
  } catch (err) {
    console.error("Error updating PPUs:", err);
    res.redirect("/admin?message=Error updating PPUs: " + err.message);
  }
});

app.post("/admin/updateVolumePricing", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const tiers = req.body.tiers;
    const updateOps = [];

    for (const tierId in tiers) {
      const tierData = tiers[tierId];
      const update = {
        id: tierData.id,
        userCount: parseInt(tierData.userCount),
        volumeDiscount: parseFloat(tierData.volumeDiscount) / 100,
        subscriptions: {}
      };

      // Process each currency price
      for (const currency in tierData.subscriptions) {
        update.subscriptions[currency] = parseFloat(tierData.subscriptions[currency]);
      }

      updateOps.push(volumePricingContainer.items.upsert(update));
    }

    await Promise.all(updateOps);
    res.redirect("/admin?message=Volume pricing updated successfully");
  } catch (err) {
    console.error("Error updating volume pricing:", err);
    res.redirect("/admin?message=Error updating volume pricing");
  }
});

// POST /admin/updateCurrencies
app.post("/admin/updateCurrencies", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const rates = req.body.rates;
    
    // Convert string values to numbers and ensure GBP is always 1.0
    const processedRates = {
      GBP: 1.0, // Force GBP to be 1.0 as it's our base
      USD: parseFloat(rates.USD) || 1.3,
      EUR: parseFloat(rates.EUR) || 1.15
    };

    // Get the latest document to update it
    const { resources: existingDocs } = await currenciesContainer.items
      .query("SELECT TOP 1 * FROM c ORDER BY c._ts DESC")
      .fetchAll();
    
    let update;
    if (existingDocs.length > 0) {
      // Update existing document
      update = {
        ...existingDocs[0],
        rates: processedRates,
        date: new Date().toISOString()
      };
    } else {
      // Create new document if none exists
      update = {
        id: "exchange-rates",
        date: new Date().toISOString(),
        rates: processedRates
      };
    }

    await currenciesContainer.items.upsert(update);
    res.redirect("/admin?message=Exchange rates updated successfully");
  } catch (err) {
    console.error("Error updating exchange rates:", err);
    res.redirect("/admin?message=Error updating exchange rates");
  }
});

app.post("/admin/addVolumeTier", /*requireOrderAdminOTP*/ async (req, res) => {
  try {
    const { userCount, volumeDiscount, subscriptions } = req.body;
    
    // Process subscriptions to convert string values to numbers
    const processedSubscriptions = {};
    for (const [currency, price] of Object.entries(subscriptions)) {
      processedSubscriptions[currency] = parseFloat(price);
    }

    const newTier = {
      id: userCount.toString(),
      userCount: parseInt(userCount),
      volumeDiscount: parseFloat(volumeDiscount) / 100,
      subscriptions: processedSubscriptions
    };

    await volumePricingContainer.items.create(newTier);
    res.redirect("/admin?message=New volume pricing tier added successfully");
  } catch (err) {
    console.error("Error adding new volume tier:", err);
    res.redirect("/admin?message=Error adding new volume pricing tier");
  }
});

// Updated delete endpoint with better error handling
app.post("/admin/deleteVolumeTier", /*requireOrderAdminOTP*/ async (req, res) => {
  const { tierId } = req.body;
  
  try {
    // Attempt to delete
    await volumePricingContainer.item(tierId, tierId).delete();
    
    // Get updated list
    const { resources: updatedTiers } = await volumePricingContainer.items
      .query("SELECT * FROM c ORDER BY c.userCount ASC")
      .fetchAll();
    
    res.json({
      success: true,
      tiers: updatedTiers,
      message: "Tier deleted successfully"
    });
    
  } catch (err) {
    console.error("Delete error:", err);
    res.status(err.code === 404 ? 404 : 500).json({
      success: false,
      message: err.code === 404 ? 
        "Tier not found (may already be deleted)" : 
        "Error deleting tier"
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
  const { amount, currency, commitmentDiscount, isCurrentSubscriber } = req.body;
  const numSubscribers = Number(amount);

  let finalPrice = 0;
  let usedVolumePricing = false;
  let ppuValue = Number(0);
  let discountMultiplier = 1;

  try {
    const { resource: discountDoc } = await discountContainer
      .item("discount-rules", "rules")
      .read();

    const commitmentPercent = parseFloat(commitmentDiscount || 0) / 100;
    const commitmentMultiplier = 1 - commitmentPercent;

    const subscriberMultiplier = isCurrentSubscriber === "on"
      ? 1 - (discountDoc.currentSubscriber || 0)
      : 1;

    discountMultiplier = commitmentMultiplier * subscriberMultiplier;

    if (numSubscribers > 1000) {
      // Volume pricing (annual price already)
      const { resources: tiers } = await volumePricingContainer.items
        .query({
          query: "SELECT * FROM c WHERE c.userCount >= @numUsers ORDER BY c.userCount ASC",
          parameters: [{ name: "@numUsers", value: numSubscribers }]
        })
        .fetchAll();

      if (tiers.length > 0) {
        const selectedTier = tiers[0];
        const volumeBasePrice = selectedTier.subscriptions[currency];

        finalPrice = volumeBasePrice * discountMultiplier; // annual price after discount
        usedVolumePricing = true;
      }
    }

    if (!usedVolumePricing) {
      // PPU fallback (monthly price)
      const ppuContainer = calcDatabase.container("PPUs");
      const { resources: ppuDocs } = await ppuContainer.items
        .query({ query: "SELECT * FROM c ORDER BY c.date DESC" })
        .fetchAll();

      const latestPPU = ppuDocs[0];
      if (!latestPPU?.ppu?.[currency]?.standard) {
        throw new Error(`No PPU found for currency ${currency}`);
      }

      ppuValue = latestPPU.ppu[currency].standard;
      const basePrice = numSubscribers * ppuValue;

      finalPrice = basePrice * discountMultiplier; // monthly price after discount
    }

    // Pass these flags so the template can know if finalPrice is monthly or annual
    res.render("result", {
      price: Number(ppuValue), // Ensure this is a number
      amount: Number(numSubscribers),
      currency,
      multi: Number((1 - discountMultiplier) * 100),
      multipliedAmount: Number(finalPrice),
      usedVolumePricing
    });

  } catch (err) {
    console.error("Calculation error:", err.message);
    res.status(500).send("Failed to calculate subscription price.");
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
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
import crypto from "crypto";

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
      maxAge: 5 * 60 * 1000, //huom. lasketaan millisekunneissa, eli näyttää tyhmältä sen takia.
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
    req.session.codeExpires = Date.now() + 10 * 60 * 1000; // 10 min expiry

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
// Routes

// GET /
app.get("/", (req, res) => {
  res.render("index");
});

// GET /form
app.get("/form", (req, res) => {
  res.render("form");
});

// GET /calculator
app.get("/calculator", (req, res) => {
  res.render("calculator");
});

//authentikointia loginille
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.redirect('/login');
}

// GET /login /orderAdminille
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// POST /login
app.post('/login', async (req, res) => {
  const { password } = req.body;
  
  try {
    // Read from adminConfig container
    const { resource: config } = await adminConfigContainer.item("adminCredentials", "adminCredentials").read();
    
    if (!config) {
      return res.render('login', { error: 'Admin configuration not found' });
    }

    const match = await bcrypt.compare(password, config.adminPassword);

    if (match) {
      req.session.authenticated = true;
      res.redirect('/orderAdmin');
    } else {
      res.render('login', { error: 'Invalid password' });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.render('login', { error: 'Login failed' });
  }
});

/// GET /orderAdmin
app.get("/orderAdmin", requireAuth, async (req, res) => {
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

    res.render("orderAdmin", {
      customers: paginatedCustomers,
      message: null,
      currentPage: page,
      totalPages: totalPages,
      searchTerm,
      limit,
      currentEmail,
      emailMessage: req.query.emailMessage || null  // Pass emailMessage from query string
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
      emailMessage: "Error fetching system email"
    });
  }
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

  const { resources: emailDoc } = await customerContainer.items
    .query({
      query: "SELECT * FROM c WHERE c.id = @id",
      parameters: [{ name: "@id", value: "sysemail" }]
    })
    .fetchAll();

  const sysemail = emailDoc[0]?.email || "";

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

  try {
    const { resource } = await customerContainer.items.create(item, {
      partitionKey: customerCompany
    });
    console.log("Inserted item into Cosmos DB:", resource);

    // Email sending logic
    const transporter = nodemailer.createTransport({
      service: 'gmail', // or 'Outlook365', 'SendGrid' etc.
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
        <p><strong>Orderer:</strong> ${ordererName}</p>
        <p><strong>Orderer email:</strong> ${ordererEmail}</p>
        <p><strong>Partner Company:</strong> ${partnerCompany}</p>
        <p><strong>Customer Company:</strong> ${customerCompany}</p>
        <p><strong>Customer Address:</strong> ${customerAddress}</p>
        <p><strong>Business Number:</strong> ${customerBusinessNumber}</p>
        <p><strong>Contact Name:</strong> ${customerContactName}</p>
        <p><strong>Contact Email:</strong> ${customerContactEmail}</p>
        <p><strong>Number of users:</strong> ${numUsers}</p>
        <p><strong>Customer price:</strong> ${customerPrice}</p>
        <p><strong>Currency:</strong> ${currency}</p>
        <p><strong>Start Date:</strong> ${startDate}</p>
        <p><strong>Initial Term:</strong> ${initialTerm} months</p>
        <p><strong>Tenant URL:</strong> ${tenantURL}</p>
        <hr />
        <p>This is an automated message.</p>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");

    // Render thank you page
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
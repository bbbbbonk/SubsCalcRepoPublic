// server.js
import express from "express";
import path, { dirname } from "path";
import { fileURLToPath } from "url";
import { config as dotenvConfig } from "dotenv";
import { CosmosClient } from "@azure/cosmos";
import { DefaultAzureCredential } from "@azure/identity";

// Enable .env support (for local development)
dotenvConfig();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
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
    tenantURL
  } = req.body;

  const item = {
    id: `${Date.now()}`, // Use timestamp for unique id
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
    startDate,
    initialTerm,
    tenantURL,
    submittedAt: new Date().toISOString()
  };

  try {
    const { resource } = await customerContainer.items.create(item, {
      partitionKey: customerCompany
    });
    console.log("Inserted item into Cosmos DB:", resource);

    // Render thankyou.ejs after successful submission
    res.render("thankyou", {
      ordererName,
      customerCompany

    });
  } catch (err) {
    console.error("Error saving to Cosmos DB:", err.message);
    res.status(500).send("Failed to save your application.");
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

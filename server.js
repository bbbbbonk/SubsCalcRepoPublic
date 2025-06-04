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

const database = cosmosClient.database("CalculatorConfigDB");
const customerDatabase = cosmosClient.database("CustomerInfo");

const container = database.container("Variables");
const customerContainer = database.container("CustomerInfo");
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
  const { name, email } = req.body;

  const item ={
    id:`${Date.now()}`,
    partitionkey:"Customer",
    name,
    email,
    submittedAt: new Date().toISOString()
  };

  try {
    const { resource } = await customerContainer.items.create(item, {
      partitionKey: item.partitionkey
    });
    console.log("Inserted item:", resource);
    res.send(`Thank you, ${name}. Your application has been received.`);
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
    const { resource: doc } = await container.item("VAR", "Sale").read();
    // Assuming your multiplier is stored in the field 'value' or 'SaleM'
    multi = doc?.DiscountPerc ?? 0;
  } catch (err) {
    console.warn("Failed to fetch multiplier from Cosmos DB:", err.message);
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

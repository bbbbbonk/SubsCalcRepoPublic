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
const container = database.container("Variables");

// Routes

// GET /
app.get("/", (req, res) => {
  res.render("index");
});

// POST /calculate
app.post("/calculate", async (req, res) => {
  const { email, amount, name } = req.body;

  let multi = 1;
  try {
    // Adjust id and partition key as needed, example assumes:
    // id = "VAR", partitionKey = "Sale2" (change as needed)
    const { resource: doc } = await container.item("VAR", "Sale").read();
    // Assuming your multiplier is stored in the field 'value' or 'SaleM'
    multi = doc?.value ?? doc?.SaleM ?? 1;
  } catch (err) {
    console.warn("Failed to fetch multiplier from Cosmos DB:", err.message);
  }

  // Calculate the multiplied amount
  const multipliedAmount = Number(amount) * multi/100;

  // Render the result page with the calculation and submitted info
  res.render("result", { email, name, amount, multipliedAmount });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Calculator app listening on port ${port}`);
});

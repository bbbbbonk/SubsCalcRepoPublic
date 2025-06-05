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

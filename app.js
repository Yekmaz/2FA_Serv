const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");

const http = require("http");

require("dotenv").config();
const port = process.env.PORT;
const domain = process.env.DOMAIN;
const db_domain = process.env.DB_DOMAIN;

const loginRoutes = require("./routes/register-routes");

const app = express();

app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "*");
  next();
});

app.use("/api/", loginRoutes);

const httpServer = http.createServer(app);

mongoose
  .connect(`${db_domain}`)
  .then(() => {
    httpServer.listen(port, () => {
      console.log(`Listening at ${domain}:${port}`);
    });
  })
  .catch((err) => console.log(err));

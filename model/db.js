const mongoose = require("mongoose");

const MONGOURI = "mongodb+srv://kiet:kiet@kiet.ov07xay.mongodb.net/";

const InitiateMongoServer = async () => {
    try {
      await mongoose.connect(MONGOURI, {
        useNewUrlParser: true
      });
      console.log("Connected to DB !!");
    } catch (e) {
      console.log(e);
      throw e;
    }
  };
  
  module.exports = { InitiateMongoServer, mongoose };


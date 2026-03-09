import jwt from "jsonwebtoken";
import Blacklist from "../models/blackListerToken.js";

export const verifyToken = async (req, res, next) => {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({ msg: "Authorization header missing" });
  }

  let token = authHeader.split(" ")[1];

  let findBlock = await Blacklist.findOne({ token });

  if (findBlock) {
    return res.status(200).send({ msg: "You are already blocked" });
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {

    if (err) {
      return res.status(401).send({ msg: "You are not authenticated person" });
    }

    req.user = decoded;
    next();
  });
};

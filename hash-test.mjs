import argon2 from "argon2";
const password = "meshack";
const hashedPassword = await argon2.hash(password);
console.log("Hashed password:", hashedPassword);

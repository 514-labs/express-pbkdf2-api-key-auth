#!/usr/bin/env node
import { generateApiKey } from "../index";

const { bearerToken, apiKeyHash } = generateApiKey();

console.log("API Key Hash (store server-side):");
console.log(apiKeyHash);
console.log("");
console.log("Bearer Token (give to client):");
console.log(bearerToken);

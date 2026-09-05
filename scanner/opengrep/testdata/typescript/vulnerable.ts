import child_process from "node:child_process";

eval(userInput);
child_process.exec(`cat ${userInput}`);
element.innerHTML = userInput;
const options = { rejectUnauthorized: false };
const sessionToken = Math.random();

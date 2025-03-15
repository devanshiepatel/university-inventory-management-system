import bcrypt from "bcrypt";

const hashPassword = async (password) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(`Hashed Password for "${password}":`, hashedPassword);
};

// 🔹 Call the function with your desired password
hashPassword("dcv123"); // Change the password as needed

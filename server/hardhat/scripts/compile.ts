import { run } from "hardhat";

async function main() {
  try {
    console.log("Compiling contracts...");
    await run("compile");
    console.log("Compilation completed successfully");
  } catch (error) {
    console.error("Error during compilation:", error);
    process.exit(1);
  }
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

export default main;

// npx hardhat run --network localhost scripts/deploy.js
const hre = require('hardhat')
require('dotenv').config()

const { 
  BRIDGE_ADDR, 
  WRAPPED_TOKEN_NAME, 
  WRAPPED_TOKEN_SYMBOL, 
  WRAPPED_TOKEN_DECIMAL 
} = process.env

async function main () {
  const wrappedToken = await hre.ethers.getContractFactory('WrappedToken')
  const wrappedTokenContract = await wrappedToken.deploy()
  await wrappedTokenContract.deployed()
  console.log('Wrapped token deployed to:', wrappedTokenContract.address)

  await wrappedTokenContract.initialize(WRAPPED_TOKEN_NAME, WRAPPED_TOKEN_SYMBOL, WRAPPED_TOKEN_DECIMAL, BRIDGE_ADDR)

  console.log('Wrapped token initialized', WRAPPED_TOKEN_NAME, WRAPPED_TOKEN_SYMBOL, WRAPPED_TOKEN_DECIMAL, BRIDGE_ADDR)
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })

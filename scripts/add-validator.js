const ethers = require('ethers');
const fs = require('fs');

const abi = JSON.parse(fs.readFileSync('./abi/Bridge.abi', 'utf8'));
const { ActionId } = require('./util');
require('dotenv').config();

const { 
  BRIDGE_ADDR, 
  RPC_PROVIDER, 
  PRIVATE_KEY, 
  VALIDATOR_ADDR,
  CHAIN_ID,
} = process.env

const VALIDATORS_PK = process.env.VALIDATORS_PK.split('|');

const provider = new ethers.providers.JsonRpcProvider(RPC_PROVIDER);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const contract = new ethers.Contract(BRIDGE_ADDR, abi, signer);

const nowPlus1Hr = Math.floor(new Date().getTime()) + 3600000;
const chainId = Number(CHAIN_ID);

async function hashAndSign(actionSupport, tokenAddress, nonce, contractAddress, expiration, chainId) {
    const types = ['uint256', 'address', 'uint256', 'address', 'uint256', 'uint32'];
    const values = [actionSupport, tokenAddress, nonce, contractAddress, expiration, chainId];

    const messageHash = ethers.utils.solidityKeccak256(types, values);

    const signatures = [];
    for (const privateKey of VALIDATORS_PK) {
        const wallet = new ethers.Wallet(privateKey);
        const signature = await wallet.signMessage(ethers.utils.arrayify(messageHash));
        signatures.push(signature);
    }

    return signatures;
}

async function main() {
    let nonce = Number((await contract.nonce()).toString());

    const signatures = await hashAndSign(ActionId.AddValidator, VALIDATOR_ADDR, nonce, BRIDGE_ADDR, nowPlus1Hr, chainId);
    console.log('Signatures:', signatures);
    const tx = await contract.addValidator(signatures, VALIDATOR_ADDR, nowPlus1Hr);
    await tx.wait();

    console.log('Validator added');
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});

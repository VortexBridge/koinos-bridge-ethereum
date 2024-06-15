const ethers = require('ethers');
const fs = require('fs');

const abi = JSON.parse(fs.readFileSync('./abi/Bridge.abi', 'utf8'));
const { ActionId } = require('./util');
require('dotenv').config();

const { 
  BRIDGE_ADDR, 
  RPC_PROVIDER, 
  PRIVATE_KEY, 
  TOKEN_ADDR 
} = process.env

const VALIDATORS_PK = process.env.VALIDATORS_PK.split('|');

const provider = new ethers.providers.JsonRpcProvider(RPC_PROVIDER);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const contract = new ethers.Contract(BRIDGE_ADDR, abi, signer);

const nowPlus1Hr = Math.floor(new Date().getTime()) + 3600000;
const fee = ethers.utils.parseUnits('0', 'ether');
const chainId = 100;

async function hashAndSign(actionSupport, tokenAddress, fee, nonce, contractAddress, expiration, chainId) {
    const types = ['uint256', 'address', 'uint256', 'uint256', 'address', 'uint256', 'uint32'];
    const values = [actionSupport, tokenAddress, fee, nonce, contractAddress, expiration, chainId];

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

    const signatures = await hashAndSign(ActionId.AddSupportedToken, TOKEN_ADDR, fee, nonce, BRIDGE_ADDR, nowPlus1Hr, chainId);
    console.log('Signatures:', signatures);
    const tx = await contract.addSupportedToken(signatures, TOKEN_ADDR, fee, nowPlus1Hr);
    await tx.wait();

    console.log('Wrapped token support added');
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});

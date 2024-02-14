import { Block } from "@nomicfoundation/ethereumjs-block";
import { Common } from "@nomicfoundation/ethereumjs-common";
import {
  bufferToBigInt,
  bufferToHex,
  toBuffer,
} from "@nomicfoundation/ethereumjs-util";
import { assert } from "chai";

import { JsonRpcClient } from "../../../../../src/internal/hardhat-network/jsonrpc/client";
import { randomHashBuffer } from "../../../../../src/internal/hardhat-network/provider/utils/random";
import {
  makeForkClient,
  getLastSafeBlockNumber,
} from "../../../../../src/internal/hardhat-network/provider/utils/makeForkClient";
import { ALCHEMY_URL } from "../../../../setup";
import {
  createTestLog,
  createTestReceipt,
  createTestTransaction,
} from "../../helpers/blockchain";
import {
  BLOCK_HASH_OF_10496585,
  BLOCK_NUMBER_OF_10496585,
  FIRST_TX_HASH_OF_10496585,
  LAST_TX_HASH_OF_10496585,
  TOTAL_DIFFICULTY_OF_BLOCK_10496585,
} from "../../helpers/constants";
import { defaultHardhatNetworkParams } from "../../../../../src/internal/core/config/default-config";

describe("ForkBlockchain", () => {
  let client: JsonRpcClient;
  let forkBlockNumber: bigint;
  let common: Common;
  let fb: ForkBlockchain;

  function createBlock(parent: Block, difficulty: bigint = 0n) {
    return Block.fromBlockData(
      {
        header: {
          number: parent.header.number + 1n,
          parentHash: parent.hash(),
          difficulty,
        },
      },
      { common, skipConsensusFormatValidation: true }
    );
  }

  function mainnetHardforkActivations() {
    return defaultHardhatNetworkParams.chains.get(1)!.hardforkHistory;
  }

  before(async function () {
    if (ALCHEMY_URL === undefined) {
      this.skip();
      return;
    }
  });

  beforeEach(async () => {
    const clientResult = await makeForkClient({ jsonRpcUrl: ALCHEMY_URL! });
    client = clientResult.forkClient;
    forkBlockNumber = clientResult.forkBlockNumber;

    common = new Common({ chain: "mainnet" });
    common.setHardfork(common.getHardforkByBlockNumber(forkBlockNumber));

    fb = new ForkBlockchain(
      client,
      forkBlockNumber,
      mainnetHardforkActivations(),
      common
    );
  });

  function hasCommonGetTransactionBehaviour(
    getTransaction: typeof fb.getTransaction | typeof fb.getLocalTransaction
  ) {
    it("returns a known transaction", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      block.transactions.push(transaction);
      await fb.addBlock(block);

      const result = await getTransaction(transaction.hash());
      assert.equal(result, transaction);
    });

    it("forgets transactions after block is removed", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      block.transactions.push(transaction);
      await fb.addBlock(block);
      await fb.deleteBlock(block.hash());

      assert.isUndefined(await getTransaction(transaction.hash()));
    });
  }

  describe("getTransaction", () => {
    hasCommonGetTransactionBehaviour((hash) => fb.getTransaction(hash));

    it("returns a known remote transaction", async () => {
      const result = await fb.getTransaction(FIRST_TX_HASH_OF_10496585);
      assert.isTrue(result?.hash().equals(FIRST_TX_HASH_OF_10496585));
    });

    it("returns undefined for newer remote transactions", async () => {
      fb = new ForkBlockchain(
        client,
        BLOCK_NUMBER_OF_10496585 - 1n,
        mainnetHardforkActivations(),
        common
      );
      assert.equal(
        await fb.getTransaction(FIRST_TX_HASH_OF_10496585),
        undefined
      );
    });
  });

  describe("getLocalTransaction", () => {
    hasCommonGetTransactionBehaviour((hash) => fb.getLocalTransaction(hash));

    it("returns undefined for a remote transaction", async () => {
      const result = fb.getLocalTransaction(FIRST_TX_HASH_OF_10496585);
      assert.isUndefined(result);
    });
  });

  describe("getBlockByTransactionHash", () => {
    it("returns undefined for unknown transactions", async () => {
      const transaction = createTestTransaction();
      assert.equal(
        await fb.getBlockByTransactionHash(transaction.hash()),
        undefined
      );
    });

    it("returns block for a known transaction", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      block.transactions.push(transaction);
      await fb.addBlock(block);

      const result = await fb.getBlockByTransactionHash(transaction.hash());
      assert.equal(result, block);
    });

    it("returns a block for known remote transaction", async () => {
      const result = await fb.getBlockByTransactionHash(
        FIRST_TX_HASH_OF_10496585
      );
      const block = await fb.getBlock(BLOCK_HASH_OF_10496585);
      assert.equal(result, block);
    });

    it("throws for newer remote transactions", async () => {
      fb = new ForkBlockchain(
        client,
        BLOCK_NUMBER_OF_10496585 - 1n,
        mainnetHardforkActivations(),
        common
      );
      await assert.isRejected(
        fb.getBlockByTransactionHash(FIRST_TX_HASH_OF_10496585),
        Error,
        "Block not found"
      );
    });

    it("forgets transactions after block is removed", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      block.transactions.push(transaction);
      await fb.addBlock(block);
      await fb.deleteBlock(block.hash());

      assert.equal(
        await fb.getBlockByTransactionHash(transaction.hash()),
        undefined
      );
    });
  });

  describe("getReceiptByTransactionHash", () => {
    it("returns undefined for unknown transactions", async () => {
      const transaction = createTestTransaction();
      assert.equal(
        await fb.getReceiptByTransactionHash(transaction.hash()),
        undefined
      );
    });

    it("returns undefined for a known transaction without receipt", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      block.transactions.push(transaction);
      await fb.addBlock(block);

      assert.equal(
        await fb.getReceiptByTransactionHash(transaction.hash()),
        undefined
      );
    });

    it("returns the receipt when it was provided earlier", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      const receipt = createTestReceipt(transaction);
      block.transactions.push(transaction);

      await fb.addBlock(block);
      fb.addTransactionReceipts([receipt]);

      assert.equal(
        await fb.getReceiptByTransactionHash(transaction.hash()),
        receipt
      );
    });

    it("returns remote receipts", async () => {
      const receipt = await fb.getReceiptByTransactionHash(
        FIRST_TX_HASH_OF_10496585
      );
      assert.equal(
        receipt?.transactionHash,
        bufferToHex(FIRST_TX_HASH_OF_10496585)
      );
    });

    it("returns undefined for newer remote receipts", async () => {
      fb = new ForkBlockchain(
        client,
        BLOCK_NUMBER_OF_10496585 - 1n,
        mainnetHardforkActivations(),
        common
      );

      assert.equal(
        await fb.getReceiptByTransactionHash(FIRST_TX_HASH_OF_10496585),
        undefined
      );
    });

    it("forgets receipts after block is removed", async () => {
      const block = createBlock(await fb.getLatestBlock());
      const transaction = createTestTransaction();
      const receipt = createTestReceipt(transaction);
      block.transactions.push(transaction);

      await fb.addBlock(block);
      fb.addTransactionReceipts([receipt]);
      await fb.deleteBlock(block.hash());

      assert.equal(
        await fb.getReceiptByTransactionHash(transaction.hash()),
        undefined
      );
    });
  });

  describe("getLogs", () => {
    it("works like BlockchainData.getLogs for new blocks", async () => {
      const block1 = createBlock(await fb.getLatestBlock());
      const number = block1.header.number;
      const log1 = createTestLog(number);
      const log2 = createTestLog(number);
      const tx1 = createTestTransaction();
      const receipt1 = createTestReceipt(tx1, [log1, log2]);
      const tx2 = createTestTransaction();
      const log3 = createTestLog(number);
      const receipt2 = createTestReceipt(tx2, [log3]);
      block1.transactions.push(tx1, tx2);

      const block2 = createBlock(block1);
      const tx3 = createTestTransaction();
      const log4 = createTestLog(number + 1n);
      const receipt3 = createTestReceipt(tx3, [log4]);
      block2.transactions.push(tx3);

      await fb.addBlock(block1);
      await fb.addBlock(block2);
      fb.addTransactionReceipts([receipt1, receipt2, receipt3]);

      const logs = await fb.getLogs({
        fromBlock: number,
        toBlock: number,
        addresses: [],
        normalizedTopics: [],
      });
      assert.deepEqual(logs, [log1, log2, log3]);
    });

    it("supports remote blocks", async () => {
      // See results at https://api.etherscan.io/api?module=logs&action=getLogs&fromBlock=10496585&toBlock=10496585&address=0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
      const logs = await fb.getLogs({
        fromBlock: BLOCK_NUMBER_OF_10496585,
        toBlock: BLOCK_NUMBER_OF_10496585,
        addresses: [toBuffer("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")],
        normalizedTopics: [],
      });
      assert.equal(logs.length, 12);
      assert.deepEqual(
        logs.map((l) => l.logIndex),
        [
          "0x1",
          "0x4",
          "0xd",
          "0xe",
          "0x11",
          "0x14",
          "0x1b",
          "0x1e",
          "0x29",
          "0x2a",
          "0x8b",
          "0x8c",
        ]
      );
    });

    it("can fetch both remote and local logs simultaneously", async () => {
      fb = new ForkBlockchain(
        client,
        BLOCK_NUMBER_OF_10496585,
        mainnetHardforkActivations(),
        common
      );

      const block1 = createBlock(await fb.getLatestBlock());
      const number = block1.header.number;
      const log1 = createTestLog(number);
      const log2 = createTestLog(number);
      const tx1 = createTestTransaction();
      const receipt1 = createTestReceipt(tx1, [log1, log2]);
      const tx2 = createTestTransaction();
      const log3 = createTestLog(number);
      const receipt2 = createTestReceipt(tx2, [log3]);
      block1.transactions.push(tx1, tx2);

      const block2 = createBlock(block1);
      const tx3 = createTestTransaction();
      const log4 = createTestLog(number + 1n);
      const receipt3 = createTestReceipt(tx3, [log4]);
      block2.transactions.push(tx3);

      await fb.addBlock(block1);
      await fb.addBlock(block2);
      fb.addTransactionReceipts([receipt1, receipt2, receipt3]);

      const logs = await fb.getLogs({
        fromBlock: BLOCK_NUMBER_OF_10496585,
        toBlock: BLOCK_NUMBER_OF_10496585 + 1n,
        addresses: [],
        normalizedTopics: [],
      });
      assert.equal(logs.length, 208);
    });
  });
});

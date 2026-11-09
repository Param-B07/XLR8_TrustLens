import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { network } from "hardhat";

const { ethers } = await network.getOrCreate();

describe("ThreatRegistry", function () {
  let registry;
  let reporter;

  beforeEach(async function () {
    [reporter] = await ethers.getSigners();
    registry = await ethers.deployContract("ThreatRegistry");
    await registry.waitForDeployment();
  });

  it("stores only the report commitment metadata and records the reporter", async function () {
    const reportId = "report-123";
    const reportHash = ethers.sha256(ethers.toUtf8Bytes('{"risk_level":"Suspicious"}'));
    const timestamp = 1_800_000_000;

    const transaction = await registry.registerReport(
      reportId,
      reportHash,
      "Suspicious",
      timestamp
    );
    const receipt = await transaction.wait();
    const eventTopic = registry.interface.getEvent("ReportCommitted").topicHash;
    const eventLog = receipt.logs.find((log) => log.topics[0] === eventTopic);
    assert.ok(eventLog);
    const event = registry.interface.parseLog(eventLog);
    assert.equal(event.args.reportId, reportId);
    assert.equal(event.args.reportHash, reportHash);
    assert.equal(event.args.riskLevel, "Suspicious");
    assert.equal(event.args.timestamp, BigInt(timestamp));
    assert.equal(event.args.reporterAddress, reporter.address);

    const commitment = await registry.getReport(reportId);
    assert.equal(commitment.reportHash, reportHash);
    assert.equal(commitment.riskLevel, "Suspicious");
    assert.equal(commitment.timestamp, BigInt(timestamp));
    assert.equal(commitment.reporterAddress, reporter.address);
    assert.equal(commitment.exists, true);
    assert.equal(await registry.verifyReport(reportId, reportHash), true);
    assert.equal(
      await registry.verifyReport(
        reportId,
        ethers.sha256(ethers.toUtf8Bytes("tampered report"))
      ),
      false
    );
  });

  it("rejects duplicate IDs, invalid risks, empty hashes, and empty IDs", async function () {
    const hash = ethers.sha256(ethers.toUtf8Bytes("report"));
    await registry.registerReport("one", hash, "Low Risk", 1_800_000_000);

    await assert.rejects(
      () => registry.registerReport("one", hash, "Low Risk", 1_800_000_001),
      /report already committed/
    );
    await assert.rejects(
      () => registry.registerReport("two", hash, "Unknown", 1_800_000_000),
      /invalid risk level/
    );
    await assert.rejects(
      () => registry.registerReport("three", ethers.ZeroHash, "Low Risk", 1_800_000_000),
      /invalid report hash/
    );
    await assert.rejects(
      () => registry.registerReport("", hash, "Low Risk", 1_800_000_000),
      /invalid report id/
    );
  });

  it("does not commit submitted URLs or message text", async function () {
    const reportId = "uuid-report";
    const reportHash = ethers.sha256(ethers.toUtf8Bytes("canonical report"));
    const secretUrl = "https://private.example/path?token=redacted";
    const secretMessage = "My OTP is 123456";
    const transaction = await registry.registerReport(
      reportId,
      reportHash,
      "High Risk",
      1_800_000_000
    );
    const receipt = await transaction.wait();
    const eventTopic = registry.interface.getEvent("ReportCommitted").topicHash;
    const eventLog = receipt.logs.find((log) => log.topics[0] === eventTopic);
    assert.ok(eventLog);
    const event = registry.interface.parseLog(eventLog);
    const eventData = JSON.stringify(
      event.args.toObject(),
      (_, value) => typeof value === "bigint" ? value.toString() : value
    );

    assert.equal(event.args.length, 5);
    assert.equal(eventData.includes(secretUrl), false);
    assert.equal(eventData.includes(secretMessage), false);
  });
});

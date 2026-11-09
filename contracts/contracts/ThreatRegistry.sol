// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatRegistry {
    struct Commitment {
        bytes32 reportHash;
        string riskLevel;
        uint64 timestamp;
        address reporterAddress;
    }

    mapping(bytes32 => Commitment) private commitments;

    event ReportCommitted(
        string reportId,
        bytes32 reportHash,
        string riskLevel,
        uint64 timestamp,
        address reporterAddress
    );

    function registerReport(
        string calldata reportId,
        bytes32 reportHash,
        string calldata riskLevel,
        uint64 timestamp
    ) external {
        require(bytes(reportId).length > 0 && bytes(reportId).length <= 128, "invalid report id");
        require(reportHash != bytes32(0), "invalid report hash");
        require(_isAllowedRiskLevel(riskLevel), "invalid risk level");
        require(timestamp > 0, "invalid timestamp");

        bytes32 reportKey = keccak256(bytes(reportId));
        require(commitments[reportKey].reportHash == bytes32(0), "report already committed");

        commitments[reportKey] = Commitment({
            reportHash: reportHash,
            riskLevel: riskLevel,
            timestamp: timestamp,
            reporterAddress: msg.sender
        });
        emit ReportCommitted(reportId, reportHash, riskLevel, timestamp, msg.sender);
    }

    function getReport(
        string calldata reportId
    )
        external
        view
        returns (
            bytes32 reportHash,
            string memory riskLevel,
            uint64 timestamp,
            address reporterAddress,
            bool exists
        )
    {
        Commitment storage commitment = commitments[keccak256(bytes(reportId))];
        exists = commitment.reportHash != bytes32(0);
        return (
            commitment.reportHash,
            commitment.riskLevel,
            commitment.timestamp,
            commitment.reporterAddress,
            exists
        );
    }

    function verifyReport(
        string calldata reportId,
        bytes32 expectedHash
    ) external view returns (bool) {
        Commitment storage commitment = commitments[keccak256(bytes(reportId))];
        return commitment.reportHash != bytes32(0) && commitment.reportHash == expectedHash;
    }

    function _isAllowedRiskLevel(string calldata riskLevel) private pure returns (bool) {
        bytes32 riskHash = keccak256(bytes(riskLevel));
        return
            riskHash == keccak256("Low Risk") ||
            riskHash == keccak256("Suspicious") ||
            riskHash == keccak256("High Risk") ||
            riskHash == keccak256("Confirmed Malicious") ||
            riskHash == keccak256("Inconclusive");
    }
}

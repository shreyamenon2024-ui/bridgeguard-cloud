
function assessTransfer(transfer) {
    let riskScore = 0;
    let reasons = [];

    const sourceChain = Number(transfer.source_chain);
    const destinationChain = Number(transfer.destination_chain);
    const quantity = Number(transfer.quantity);
    const nonce = Number(transfer.nonce);

    if (!Number.isSafeInteger(sourceChain) || sourceChain !== 31337) {
        riskScore += 40;
        reasons.push("Unexpected or invalid source chain ID");
    }

    if (!Number.isSafeInteger(destinationChain) || destinationChain !== 31337) {
        riskScore += 40;
        reasons.push("Unexpected or invalid destination chain ID");
    }

    if (
        typeof transfer.certificate_hash !== "string" ||
        !/^0x[0-9a-fA-F]{64}$/.test(transfer.certificate_hash) ||
        /^0x0{64}$/i.test(transfer.certificate_hash)
    ) {
        riskScore += 50;
        reasons.push("Invalid or missing certificate hash");
    }

    if (
        transfer.quantity == null ||
        transfer.quantity === "" ||
        !Number.isSafeInteger(quantity) ||
        quantity <= 0
    ) {
        riskScore += 40;
        reasons.push("Invalid batch quantity");
    }

    if (
        transfer.nonce == null ||
        transfer.nonce === "" ||
        !Number.isSafeInteger(nonce) ||
        nonce < 0
    ) {
        riskScore += 40;
        reasons.push("Invalid transfer nonce");
    }

    let riskStatus = "LOW";

    if (riskScore >= 50) {
        riskStatus = "HIGH";
    } else if (riskScore >= 30) {
        riskStatus = "MEDIUM";
    }

    return {
        risk_score: riskScore,
        risk_status: riskStatus,
        reasons: reasons
    };
}

module.exports = { assessTransfer };

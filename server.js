require("dotenv").config();
const { assessTransfer } = require("./security");

const express = require("express");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.static("public"));

app.use(express.json());

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);

app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        service: "Pharma Cross-Chain Security Service"
    });
});

app.get("/transfers", async (req, res) => {
    const { data, error } = await supabase
        .from("transfers")
        .select("*")
        .order("created_at", { ascending: false });

    if (error) {
        return res.status(500).json({
            error: error.message
        });
    }

    res.json(data);
});
app.post("/transfers", async (req, res) => {
    const {
        batch_id,
        source_chain,
        destination_chain,
        quantity,
        certificate_hash,
        nonce,
        risk_score,
        risk_status,
        transfer_status,
        transaction_hash
    } = req.body;

    const { data, error } = await supabase
        .from("transfers")
        .insert([
            {
                batch_id,
                source_chain,
                destination_chain,
                quantity,
                certificate_hash,
                nonce,
                risk_score,
                risk_status,
                transfer_status,
                transaction_hash
            }
        ])
        .select();

    if (error) {
        return res.status(500).json({
            error: error.message
        });
    }

    res.status(201).json(data[0]);
});


app.post("/assess", async (req, res) => {
   
const transfer = req.body;
const result = assessTransfer(transfer);

if (
    transfer.source_chain != null &&
    transfer.destination_chain != null &&
    transfer.nonce != null
) {
    const { data: existing, error: duplicateError } = await supabase
        .from("transfers")
        .select("id")
        .eq("source_chain", transfer.source_chain)
        .eq("destination_chain", transfer.destination_chain)
        .eq("nonce", transfer.nonce)
        .limit(1);

    if (duplicateError) {
        return res.status(500).json({
            error: "Could not check for duplicate nonce",
            details: duplicateError.message
        });
    }

    if (existing && existing.length > 0) {
        result.risk_score += 40;
        result.reasons.push("Duplicate transfer nonce detected");

        if (result.risk_score >= 50) {
            result.risk_status = "HIGH";
        } else if (result.risk_score >= 30) {
            result.risk_status = "MEDIUM";
        } else {
            result.risk_status = "LOW";
        }
    }
}


    const {
        batch_id,
        source_chain,
        destination_chain,
        quantity,
        certificate_hash,
        nonce,
        transaction_hash
    } = transfer;

    if (
        batch_id == null ||
        source_chain == null ||
        destination_chain == null ||
        quantity == null ||
        !certificate_hash ||
        nonce == null
    ) {
        return res.status(400).json({
            error: "Missing required transfer fields"
        });
    }

    const transferStatus =
        result.risk_status === "LOW" ? "VERIFIED" : "FLAGGED";

    const { data, error } = await supabase
        .from("transfers")
        .insert([{
            batch_id,
            source_chain,
            destination_chain,
            quantity,
            certificate_hash,
            nonce,
            
risk_score: result.risk_score,
risk_status: result.risk_status,
risk_reasons: result.reasons,
transfer_status: transferStatus,
transaction_hash: transaction_hash || null

        }])
        .select()
        .single();

    if (error) {
        return res.status(500).json({
            error: "Failed to save assessment",
            details: error.message,
            assessment: result
        });
    }

    res.status(201).json({
        message: "Risk assessment completed and saved",
        assessment: result,
        transfer: data
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Cloud service running on port ${PORT}`);
});
require("dotenv").config();
const { assessTransfer } = require("./security");

const express = require("express");
const { createClient } = require("@supabase/supabase-js");
const { JsonRpcProvider, Interface } = require("ethers");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

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
    transfer.nonce != null &&
    transfer.batch_id != null
) {
    let query = supabase
        .from("transfers")
        .select("id, transaction_hash")
        .eq("source_chain", transfer.source_chain)
        .eq("destination_chain", transfer.destination_chain)
        .eq("nonce", transfer.nonce)
        .eq("batch_id", transfer.batch_id)
        .not("transaction_hash", "is", null);

    if (transfer.transaction_hash) {
        query = query.neq(
            "transaction_hash",
            transfer.transaction_hash
        );
    }

    const { data: existing, error: duplicateError } =
        await query.limit(1);

    if (duplicateError) {
        return res.status(500).json({
            error: "Could not check for duplicate transfer",
            details: duplicateError.message
        });
    }

    if (existing && existing.length > 0) {
        result.risk_score += 40;
        result.reasons.push(
            "Different transaction detected for the same batch and nonce"
        );

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


const chainAProvider = new JsonRpcProvider("http://127.0.0.1:8545");
const chainBProvider = new JsonRpcProvider("http://127.0.0.1:8546");

const chainAAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const chainBAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

const chainAArtifactPath = path.join(
    __dirname,
    "..",
    "artifacts",
    "contracts",
    "PharmaBridgeA.sol",
    "PharmaBridgeA.json"
);

const chainBArtifactPath = path.join(
    __dirname,
    "..",
    "artifacts",
    "contracts",
    "PharmaBridgeB.sol",
    "PharmaBridgeB.json"
);

const chainAInterface = fs.existsSync(chainAArtifactPath)
    ? new Interface(
        JSON.parse(fs.readFileSync(chainAArtifactPath, "utf8")).abi
      )
    : null;

const chainBInterface = fs.existsSync(chainBArtifactPath)
    ? new Interface(
        JSON.parse(fs.readFileSync(chainBArtifactPath, "utf8")).abi
      )
    : null;

async function readBridgeEvents(
    provider,
    contractAddress,
    contractInterface,
    eventNames,
    chainName
) {
    const latestBlock = await provider.getBlockNumber();
    const fromBlock = Math.max(0, latestBlock - 999);

    const eventGroups = await Promise.all(
        eventNames.map(async (eventName) => {
            const fragment = contractInterface.getEvent(eventName);

            if (!fragment) {
                throw new Error(
                    `Event ${eventName} not found in ${chainName} ABI`
                );
            }

            const logs = await provider.getLogs({
                address: contractAddress,
                topics: contractInterface.encodeFilterTopics(
                    fragment,
                    []
                ),
                fromBlock,
                toBlock: latestBlock
            });

            return logs.map((log) => {
                const parsed = contractInterface.parseLog(log);

                const args = {};

                for (let i = 0; i < fragment.inputs.length; i++) {
                    const input = fragment.inputs[i];
                    args[input.name || `arg${i}`] =
                        String(parsed.args[i]);
                }

                return {
                    chain: chainName,
                    event: parsed.name,
                    blockNumber: log.blockNumber,
                    transactionHash: log.transactionHash,
                    args
                };
            });
        })
    );

    return eventGroups
        .flat()
        .sort((a, b) => b.blockNumber - a.blockNumber);
}

app.get("/chain-events", async (req, res) => {
        if (!chainAInterface || !chainBInterface) {
        return res.status(503).json({
            success: false,
            error: "Blockchain monitoring is unavailable in this cloud deployment."
        });
    }
    try {
        const [chainAEvents, chainBEvents] = await Promise.all([
            readBridgeEvents(
                chainAProvider,
                chainAAddress,
                chainAInterface,
                ["BatchLockedForTransfer", "BatchUnlocked"],
                "CHAIN_A"
            ),
            readBridgeEvents(
                chainBProvider,
                chainBAddress,
                chainBInterface,
                ["BatchMinted", "BatchBurned"],
                "CHAIN_B"
            )
        ]);

        const events = [...chainAEvents, ...chainBEvents]
            .sort((a, b) => b.blockNumber - a.blockNumber)
            .slice(0, 50);

        res.json({
            success: true,
            scannedFromRecentBlocks: 1000,
            chainA: {
                latestBlock: await chainAProvider.getBlockNumber(),
                eventsFound: chainAEvents.length
            },
            chainB: {
                latestBlock: await chainBProvider.getBlockNumber(),
                eventsFound: chainBEvents.length
            },
            events
        });
    } catch (error) {
        console.error("Chain event monitoring failed:", error.message);

        res.status(500).json({
            success: false,
            error: "Could not read blockchain events",
            details: error.message
        });
    }
});

app.get("/reconciliation", async (req, res) => {
        if (!chainAInterface || !chainBInterface) {
        return res.status(503).json({
            success: false,
            error: "On-chain reconciliation is unavailable in this cloud deployment."
        });
    }
    try {
        // 1. Load saved cloud assessments.
        const { data: transfers, error } = await supabase
            .from("transfers")
            .select("*")
            .order("created_at", { ascending: false });

        if (error) {
            throw new Error("Could not load assessments: " + error.message);
        }

        // 2. Read the actual events from both chains.
        const [chainAEvents, chainBEvents] = await Promise.all([
            readBridgeEvents(
                chainAProvider,
                chainAAddress,
                chainAInterface,
                ["BatchLockedForTransfer", "BatchUnlocked"],
                "CHAIN_A"
            ),
            readBridgeEvents(
                chainBProvider,
                chainBAddress,
                chainBInterface,
                ["BatchMinted", "BatchBurned"],
                "CHAIN_B"
            )
        ]);

        const locks = chainAEvents.filter(
            event => event.event === "BatchLockedForTransfer"
        );

        const mints = chainBEvents.filter(
            event => event.event === "BatchMinted"
        );

        // 3. Compare every assessment with the on-chain evidence.
        const results = transfers.map(transfer => {
            const batchId = String(transfer.batch_id);
            const nonce = String(transfer.nonce);
            const quantity = String(transfer.quantity);
            const riskStatus = String(transfer.risk_status || "")
                .toUpperCase();

            const batchLocks = locks.filter(
                event => String(event.args.batchId) === batchId
            );

            const lock = batchLocks.find(
                event => String(event.args.nonce) === nonce
            );

            const batchMints = mints.filter(
                event => String(event.args.batchId) === batchId
            );

            const mint = batchMints.find(
                event => String(event.args.nonce) === nonce
            );

            const reasons = [];
            let status = "UNKNOWN";

            if (!lock) {
                if (batchLocks.length > 0) {
                    status = "MISMATCH";
                    reasons.push(
                        "A source lock exists, but its nonce differs from the assessment."
                    );
                } else {
                    reasons.push(
                        "No matching source lock was found in the scanned blockchain history."
                    );
                }
            } else {
                // Validate the assessment against the source lock.
                if (String(lock.args.quantity) !== quantity) {
                    reasons.push("Quantity differs from the source lock.");
                }

                if (
                    String(lock.args.destinationChainId) !==
                    String(transfer.destination_chain)
                ) {
                    reasons.push(
                        "Destination chain differs from the source lock."
                    );
                }

                if (
                    transfer.transaction_hash &&
                    String(transfer.transaction_hash).toLowerCase() !==
                    String(lock.transactionHash).toLowerCase()
                ) {
                    reasons.push(
                        "Stored transaction hash differs from the source lock transaction."
                    );
                }

                // Validate any corresponding destination mint.
                if (mint) {
                    if (String(mint.args.quantity) !== quantity) {
                        reasons.push(
                            "Minted quantity differs from the assessment."
                        );
                    }

                    if (
                        String(mint.args.quantity) !==
                        String(lock.args.quantity)
                    ) {
                        reasons.push(
                            "Minted quantity differs from the source lock."
                        );
                    }
                } else if (batchMints.length > 0) {
                    reasons.push(
                        "A mint exists for this batch, but its nonce differs."
                    );
                }

                const hasMismatch = reasons.length > 0;

                if (hasMismatch) {
                    status = "MISMATCH";
                } else if (riskStatus !== "LOW") {
                    status = mint ? "MISMATCH" : "BLOCKED";
                    reasons.push(
                        mint
                            ? "A destination mint exists despite a non-LOW cloud assessment."
                            : "Cloud risk assessment did not approve minting."
                    );
                } else if (mint) {
                    status = "COMPLETED";
                    reasons.push(
                        "Source lock and destination mint match the assessment."
                    );
                } else {
                    status = "PENDING";
                    reasons.push(
                        "Source lock is confirmed, but no matching destination mint was found."
                    );
                }
            }

            return {
                assessmentId: transfer.id,
                batchId,
                sourceChain: transfer.source_chain,
                destinationChain: transfer.destination_chain,
                quantity,
                nonce,
                riskScore: transfer.risk_score,
                riskStatus,
                status,
                stages: {
                    sourceLocked: Boolean(lock),
                    cloudAssessed: true,
                    cloudApproved: riskStatus === "LOW",
                    destinationMinted: Boolean(mint)
                },
                evidence: {
                    sourceLockTransaction: lock?.transactionHash || null,
                    destinationMintTransaction: mint?.transactionHash || null
                },
                reasons
            };
        });

        const counts = {
            COMPLETED: 0,
            BLOCKED: 0,
            PENDING: 0,
            MISMATCH: 0,
            UNKNOWN: 0
        };

        for (const result of results) {
            counts[result.status]++;
        }

        res.json({
            success: true,
            generatedAt: new Date().toISOString(),
            scannedFromRecentBlocks: 1000,
            totalAssessments: results.length,
            counts,
            results
        });
    } catch (error) {
        console.error("Reconciliation failed:", error.message);

        res.status(500).json({
            success: false,
            error: "Could not reconcile transfers",
            details: error.message
        });
    }
});


const LOCAL_OPERATIONS_ENABLED =
    process.env.ENABLE_LOCAL_BRIDGE_OPERATIONS === "true";

let bridgeOperation = {
    running: false,
    status: "IDLE",
    output: "",
    startedAt: null,
    finishedAt: null,
    exitCode: null
};

// Start the existing local BridgeGuard workflow.
app.post("/operations/start", (req, res) => {
    if (!LOCAL_OPERATIONS_ENABLED) {
        return res.status(403).json({
            error: "Local blockchain operations are disabled."
        });
    }

    if (bridgeOperation.running) {
        return res.status(409).json({
            error: "A BridgeGuard operation is already running."
        });
    }

    const projectRoot = path.resolve(__dirname, "..");
    const scriptPath = path.join(
        projectRoot,
        "scripts",
        "runBridgeGuard.ps1"
    );

    bridgeOperation = {
        running: true,
        status: "RUNNING",
        output: "",
        startedAt: new Date().toISOString(),
        finishedAt: null,
        exitCode: null
    };

    const processHandle = spawn(
        "powershell.exe",
        [
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            scriptPath
        ],
        {
            cwd: projectRoot,
            windowsHide: true
        }
    );

    const appendOutput = (chunk) => {
        bridgeOperation.output =
            (bridgeOperation.output + chunk.toString()).slice(-100000);
    };

    processHandle.stdout.on("data", appendOutput);
    processHandle.stderr.on("data", appendOutput);

    processHandle.on("error", (error) => {
        bridgeOperation.output +=
            "\nCould not start workflow: " + error.message;
        bridgeOperation.running = false;
        bridgeOperation.status = "FAILED";
        bridgeOperation.finishedAt = new Date().toISOString();
    });

    processHandle.on("close", (code) => {
        bridgeOperation.running = false;
        bridgeOperation.exitCode = code;
        bridgeOperation.finishedAt = new Date().toISOString();

        const output = bridgeOperation.output;

        if (output.includes("MINT BLOCKED")) {
            bridgeOperation.status = "BLOCKED";
        } else if (
            code === 0 &&
            output.includes("SECURE MINT SUCCESSFUL")
        ) {
            bridgeOperation.status = "COMPLETED";
        } else if (code === 0) {
            bridgeOperation.status = "FINISHED";
        } else {
            bridgeOperation.status = "FAILED";
        }
    });

    res.status(202).json({
        accepted: true,
        message: "BridgeGuard workflow started.",
        status: bridgeOperation.status
    });
});

// Read the current operation status and output.
app.get("/operations/status", (req, res) => {
    res.json(bridgeOperation);
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Cloud service running on port ${PORT}`);
});


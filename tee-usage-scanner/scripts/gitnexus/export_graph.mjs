#!/usr/bin/env node

import fs from "fs/promises";
import path from "path";
import process from "process";

function parseArgs(argv) {
  const args = {
    gitnexusRoot: process.env.GITNEXUS_ROOT || path.join(process.env.HOME || "", "apps", "GitNexus"),
    repo: "",
    out: "",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--gitnexus-root") {
      args.gitnexusRoot = argv[++i] || "";
    } else if (arg === "--repo") {
      args.repo = argv[++i] || "";
    } else if (arg === "--out") {
      args.out = argv[++i] || "";
    }
  }

  if (!args.repo || !args.out) {
    throw new Error("usage: export_graph.mjs --repo <repo-path> --out <graph-json> [--gitnexus-root <dir>]");
  }

  args.gitnexusRoot = path.resolve(args.gitnexusRoot);
  args.repo = path.resolve(args.repo);
  args.out = path.resolve(args.out);
  return args;
}

function normalizeNode(node) {
  const props = node?.properties || {};
  return {
    id: node?.id || "",
    type: node?.label || "",
    name: props.name || "",
    path: props.filePath || "",
    file: props.filePath || "",
    language: props.language || "",
    properties: props,
  };
}

function normalizeRelationship(rel) {
  return {
    id: rel?.id || "",
    source: rel?.sourceId || "",
    target: rel?.targetId || "",
    type: rel?.type || "",
    confidence: rel?.confidence ?? 0,
    reason: rel?.reason || "",
    step: rel?.step,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const pipelineModule = path.join(args.gitnexusRoot, "gitnexus", "dist", "core", "ingestion", "pipeline.js");

  const { runPipelineFromRepo } = await import(`file://${pipelineModule}`);
  const progressLog = [];
  const result = await runPipelineFromRepo(args.repo, (progress) => {
    const message = `${progress.phase}:${progress.percent}`;
    if (progressLog.length === 0 || progressLog[progressLog.length - 1] !== message) {
      progressLog.push(message);
    }
  });

  const payload = {
    schema_version: "teecheck.gitnexus.graph.v1",
    source_path: result.repoPath,
    stats: {
      files: result.totalFileCount,
      nodes: result.graph.nodeCount,
      edges: result.graph.relationshipCount,
      communities: result.communityResult?.communities?.length || 0,
      processes: result.processResult?.processes?.length || 0,
    },
    progress: progressLog,
    nodes: result.graph.nodes.map(normalizeNode),
    edges: result.graph.relationships.map(normalizeRelationship),
  };

  await fs.mkdir(path.dirname(args.out), { recursive: true });
  await fs.writeFile(args.out, JSON.stringify(payload, null, 2), "utf8");

  process.stdout.write(`${args.out}\n`);
}

main().catch((error) => {
  console.error(error?.stack || String(error));
  process.exit(1);
});

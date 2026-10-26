import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFileStore } from "@/lib/store/fileStore";
import type { AnalysisResult } from "@/types/analysis";

function fakeResult(id: string): AnalysisResult {
  return { id, target: `${id}.example` } as AnalysisResult;
}

let dir: string;
let storeFile: string;

beforeEach(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "sentinelscope-store-"));
  storeFile = path.join(dir, "analyses.json");
});

afterEach(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

describe("file store", () => {
  it("returns null for an unknown id when no file exists yet", async () => {
    expect(await createFileStore(dir).getAnalysis("missing")).toBeNull();
  });

  it("saves and retrieves analyses by id, newest first on disk", async () => {
    const store = createFileStore(dir);
    await store.saveAnalysis(fakeResult("a"));
    await store.saveAnalysis(fakeResult("b"));

    expect(await store.getAnalysis("a")).toMatchObject({ id: "a" });
    const onDisk = JSON.parse(await fs.readFile(storeFile, "utf-8")) as AnalysisResult[];
    expect(onDisk.map((r) => r.id)).toEqual(["b", "a"]);
  });

  it("serializes concurrent saves so none are lost", async () => {
    const store = createFileStore(dir);
    await Promise.all(Array.from({ length: 20 }, (_, i) => store.saveAnalysis(fakeResult(`r${i}`))));
    const onDisk = JSON.parse(await fs.readFile(storeFile, "utf-8")) as AnalysisResult[];
    expect(onDisk).toHaveLength(20);
  });

  it("keeps at most 200 entries", async () => {
    await fs.writeFile(storeFile, JSON.stringify(Array.from({ length: 200 }, (_, i) => fakeResult(`old${i}`))));
    const store = createFileStore(dir);
    await store.saveAnalysis(fakeResult("new"));
    const onDisk = JSON.parse(await fs.readFile(storeFile, "utf-8")) as AnalysisResult[];
    expect(onDisk).toHaveLength(200);
    expect(onDisk[0]!.id).toBe("new");
  });

  it("does not overwrite a corrupt store file, and refuses to read it", async () => {
    await fs.writeFile(storeFile, "{ this is not json");
    const store = createFileStore(dir);

    await store.saveAnalysis(fakeResult("x")); // logged, not thrown
    expect(await fs.readFile(storeFile, "utf-8")).toBe("{ this is not json");
    await expect(store.getAnalysis("x")).rejects.toThrow();
  });

  it("keeps accepting writes after a failed one", async () => {
    await fs.writeFile(storeFile, "corrupt");
    const store = createFileStore(dir);
    await store.saveAnalysis(fakeResult("fails"));

    await fs.writeFile(storeFile, "[]"); // the problem is fixed
    await store.saveAnalysis(fakeResult("works"));
    expect(await store.getAnalysis("works")).toMatchObject({ id: "works" });
  });

  it("leaves no temp file behind after a write", async () => {
    await createFileStore(dir).saveAnalysis(fakeResult("a"));
    expect(await fs.readdir(dir)).toEqual(["analyses.json"]);
  });
});

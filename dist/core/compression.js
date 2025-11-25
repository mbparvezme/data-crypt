export const compressData = async (data) => {
    if (typeof CompressionStream === 'undefined') {
        throw new Error('CompressionStream not supported (requires Node 18+ or modern browser)');
    }
    const stream = new CompressionStream('gzip');
    const writer = stream.writable.getWriter();
    writer.write(data);
    writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
};
export const decompressData = async (data) => {
    if (typeof DecompressionStream === 'undefined') {
        throw new Error('DecompressionStream not supported');
    }
    const stream = new DecompressionStream('gzip');
    const writer = stream.writable.getWriter();
    writer.write(data);
    writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
};
export const isGzipped = (data) => data.length > 2 && data[0] === 0x1f && data[1] === 0x8b;

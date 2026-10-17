/**
 * Offset maps of the normalization stages. Entry i of a stage's map is the
 * index in the stage's input that code unit i of its output came from.
 *
 * A map is held as a Uint32Array, whose storage is outside the JavaScript
 * heap, and is undefined where it is the identity, so a stage that leaves
 * every code unit at its own index allocates no map.
 */
export type OffsetMap = Uint32Array | undefined;

/**
 * Builds the map of a stage as the stage appends to its output. Storage is
 * allocated at the first code unit that did not come from its own index, with
 * room for `capacity` code units; until then the map is the identity.
 */
export class OffsetMapBuilder {
  private map: Uint32Array | undefined;
  private length = 0;

  constructor(private readonly capacity: number) {}

  /** Appends `count` code units that came from input[from], input[from + 1] and so on. */
  copy(from: number, count: number): void {
    if (count === 0) return;
    if (this.map === undefined && from === this.length) {
      this.length += count;
      return;
    }
    const map = this.reserve(count);
    for (let k = 0; k < count; k += 1) map[this.length + k] = from + k;
    this.length += count;
  }

  /** Appends `count` code units that all came from input[from]. */
  repeat(from: number, count: number): void {
    if (count <= 1) {
      if (count === 1) this.copy(from, 1);
      return;
    }
    this.reserve(count).fill(from, this.length, this.length + count);
    this.length += count;
  }

  /** The map, or undefined when it is the identity. */
  finish(): OffsetMap {
    return this.map?.subarray(0, this.length);
  }

  private reserve(count: number): Uint32Array {
    const needed = this.length + count;
    if (this.map === undefined) {
      this.map = new Uint32Array(Math.max(needed, this.capacity));
      for (let i = 0; i < this.length; i += 1) this.map[i] = i;
    } else if (needed > this.map.length) {
      const grown = new Uint32Array(Math.max(needed, Math.ceil(this.map.length * 1.5)));
      grown.set(this.map.subarray(0, this.length));
      this.map = grown;
    }
    return this.map;
  }
}

/**
 * The map from `outer`'s output, of `length` code units, to `inner`'s input:
 * entry i is inner[outer[i]]. `outer` maps into `inner`'s output, so each of
 * its entries is an index into `inner`. An identity `outer` can be shorter
 * than `inner`, when its stage removed only code units at the end.
 */
export function composeOffsetMaps(outer: OffsetMap, inner: OffsetMap, length: number): OffsetMap {
  if (inner === undefined) return outer;
  if (outer === undefined) return inner.subarray(0, length);
  const composed = new Uint32Array(length);
  for (let i = 0; i < length; i += 1) composed[i] = inner[outer[i]];
  return composed;
}

/** `map` as a Uint32Array of `length` entries; the identity when `map` is undefined. */
export function offsetMapOrIdentity(map: OffsetMap, length: number): Uint32Array {
  if (map !== undefined) return map;
  const identity = new Uint32Array(length);
  for (let i = 0; i < length; i += 1) identity[i] = i;
  return identity;
}

/** `map` as a number[] of `length` entries; the identity when `map` is undefined. */
export function offsetMapToArray(map: ArrayLike<number> | undefined, length: number): number[] {
  if (map !== undefined) return Array.from(map);
  const identity = new Array<number>(length);
  for (let i = 0; i < length; i += 1) identity[i] = i;
  return identity;
}

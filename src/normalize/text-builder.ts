/**
 * The output text of a normalization stage, built from the pieces the stage
 * appends in order: runs of its input that it leaves as they are, and the text
 * it puts in place of what it changes.
 *
 * On Node 26.12, Array.prototype.push throws RangeError "Invalid array length"
 * on an array that holds 134217728 entries. The NFKC stage held its pieces in
 * one array, two for each code point of a text of 157286399 copies of U+1F600,
 * and threw. Here the pieces are joined into one string each time
 * PIECES_PER_JOIN of them are held. An empty piece is not held, so each of
 * those strings is at least PIECES_PER_JOIN code units long, and an output of
 * at most buffer.constants.MAX_STRING_LENGTH code units (536870888 on Node
 * 26.12) is joined from at most 8191 of them and the pieces after them.
 */
export const PIECES_PER_JOIN = 65536;

export class TextBuilder {
  private pieces: string[] = [];
  /** The pieces appended before `pieces`, joined PIECES_PER_JOIN at a time. */
  private readonly joined: string[] = [];

  /** Appends `text` to the output. */
  append(text: string): void {
    if (text.length === 0) return;
    this.pieces.push(text);
    if (this.pieces.length === PIECES_PER_JOIN) {
      this.joined.push(this.pieces.join(''));
      this.pieces = [];
    }
  }

  /** The output: every piece appended, in order, as one string. */
  finish(): string {
    const rest = this.pieces.join('');
    if (this.joined.length === 0) return rest;
    this.joined.push(rest);
    return this.joined.join('');
  }
}

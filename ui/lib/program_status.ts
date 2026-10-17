// Matches OSC 7501 sequences: ESC ] 7501 ; ... terminated by BEL or ESC \ (ST).
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching terminal escape sequences
const OSC_7501 = /\x1b\]7501;[^\x07\x1b]*(?:\x07|\x1b\\)/g;

// stripProgramStatus removes OSC 7501 program status reports and feature
// queries from terminal output text.
export function stripProgramStatus(text: string): string {
  return text.replace(OSC_7501, "");
}

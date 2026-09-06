export class EntropyCalculator {
  public static calculate(str: string): number {
    if (!str || str.length === 0) return 0;

    const frequencies = new Map<string, number>();
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;

    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(3));
  }

  public static maskSecret(secret: string): string {
    if (secret.length <= 8) return '****';
    const prefix = secret.slice(0, 4);
    const suffix = secret.slice(-4);
    return `${prefix}...${suffix}`;
  }
}

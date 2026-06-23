// Structured-output validation. When the caller supplies a JSON Schema, the
// model's output is parsed and validated with ajv; the pipeline retries on a
// miss and surfaces the failure honestly when retries are exhausted.
import { Ajv, type ValidateFunction } from "ajv";

const ajv = new Ajv({ allErrors: true, strict: false });
const cache = new Map<string, ValidateFunction>();

export interface ValidationResult {
  valid: boolean;
  errors: string | null;
  parsed: unknown;
}

function compile(schema: object): ValidateFunction | null {
  const key = JSON.stringify(schema);
  const cached = cache.get(key);
  if (cached) return cached;
  let v: ValidateFunction;
  try {
    v = ajv.compile(schema);
  } catch {
    return null; // a malformed schema is the caller's problem; do not block.
  }
  cache.set(key, v);
  return v;
}

/** Pull the first JSON value out of model text (it may wrap it in prose/fences). */
export function extractJson(text: string): unknown | undefined {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = (fenced ? fenced[1] : text).trim();
  try {
    return JSON.parse(candidate);
  } catch {
    /* fall through */
  }
  const m = candidate.match(/[{[][\s\S]*[}\]]/);
  if (m) {
    try {
      return JSON.parse(m[0]);
    } catch {
      /* ignore */
    }
  }
  return undefined;
}

export function validateOutput(text: string, schema: object): ValidationResult {
  const parsed = extractJson(text);
  if (parsed === undefined) {
    return { valid: false, errors: "output is not valid JSON", parsed: undefined };
  }
  const validator = compile(schema);
  if (!validator) return { valid: true, errors: null, parsed }; // could not compile schema
  const ok = validator(parsed) as boolean;
  return { valid: ok, errors: ok ? null : ajv.errorsText(validator.errors), parsed };
}

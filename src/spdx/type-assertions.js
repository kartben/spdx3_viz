// @ts-check
/**
 * Compile-time assertions (no runtime effect, imported by nothing) so
 * `npm run typecheck` fails if the SpdxClass typing stops constraining names.
 *
 * @module spdx/type-assertions
 */
import { isA, CLASS } from './model.js';

isA('x', 'software_Package');
isA('x', CLASS.functionalsafety_RequirementVerification);

// @ts-expect-error — not a real SPDX class name.
isA('x', 'ai_AIPackge');
// @ts-expect-error — not a real SPDX class name.
isA('x', CLASS.software_Packge);

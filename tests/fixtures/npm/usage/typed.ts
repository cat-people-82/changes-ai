import type { Foo } from "@scope/pkg/sub";
import * as ns from "lib";
const value: Foo | null = null;
ns.run(value);

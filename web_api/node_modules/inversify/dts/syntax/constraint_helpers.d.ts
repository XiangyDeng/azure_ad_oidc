import interfaces from "../interfaces/interfaces";
declare let traverseAncerstors: (request: interfaces.Request, constraint: interfaces.ConstraintFunction) => boolean;
declare let taggedConstraint: (key: string) => (value: any) => interfaces.ConstraintFunction;
declare let namedConstraint: (value: any) => interfaces.ConstraintFunction;
declare let typeConstraint: (type: string | Function) => (request: interfaces.Request) => boolean;
export { traverseAncerstors, taggedConstraint, namedConstraint, typeConstraint };

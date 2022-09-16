import interfaces from "../interfaces/interfaces";
declare class Metadata implements interfaces.Metadata {
    key: string;
    value: any;
    constructor(key: string, value: any);
    toString(): string;
}
export default Metadata;

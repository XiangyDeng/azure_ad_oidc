declare function tagged(metadataKey: string, metadataValue: any): (target: any, targetKey: string, index?: number) => any;
export default tagged;

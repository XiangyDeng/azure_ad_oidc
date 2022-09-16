import interfaces from "../interfaces/interfaces";
declare function inject(serviceIdentifier: interfaces.ServiceIdentifier<any>): (target: any, targetKey: string, index?: number) => any;
export default inject;

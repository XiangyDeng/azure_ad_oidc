import interfaces from "../interfaces/interfaces";
declare function tagParameter(annotationTarget: any, propertyName: string, parameterIndex: number, metadata: interfaces.Metadata): any;
declare function tagProperty(annotationTarget: any, propertyName: string, metadata: interfaces.Metadata): any;
declare function decorate(decorator: (ClassDecorator | ParameterDecorator), target: any, parameterIndex?: number): void;
export { decorate, tagParameter, tagProperty };

export const MAVEN = 'maven';

export class ComponentIdentifier {
    format: string;
    coordinates: Map<string, string | undefined>;

    constructor(format: string, coordinates: Map<string, string>) {
        this.format = format;
        this.coordinates = coordinates;
    }

    getName(): string {
        return this.coordinates!.get('artifactId')!;
    }

    getVersion(): string {
        const version = this.coordinates.get('version');
        return version ? version : 'n/a';
    }

    setVersion(version: string): void {
        this.coordinates.set('version', version);
    }

    equals(b: ComponentIdentifier | undefined): boolean {
        if (b === undefined) {
            return false;
        }
        if (this === b) {
            return true;
        }
        if (this.format !== b.format) {
            return false;
        }
        for (const key of this.coordinates.keys()) {
            if (this.coordinates.get(key) !== b.coordinates.get(key)) {
                return false;
            }
        }
        for (const key of b.coordinates.keys()) {
            if (!this.coordinates.has(key)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @returns a simpler JSON, used in IQ API requests and responses, in which the `coordinates` look like a plain object
     */
    toJson(): string {
        return JSON.stringify(this, ComponentIdentifier.replacer);
    }

    public static replacer(key: string, value: object) {
        if (key === 'coordinates' && value instanceof Map) {
            let result = '{';
            for (const entry of value) {
                result += (result.length > 1 ? ',"' : '"') + entry[0] + '":"' + entry[1] + '"';
            }
            return JSON.parse(result + '}');
        }
        return value;
    }

    static createMavenIdentifier(
        groupId: string,
        artifactId: string,
        extension: string,
        classifier: string,
        version: string
    ): ComponentIdentifier {
        const coordinates = new Map<string, string>();
        coordinates.set('groupId', groupId);
        coordinates.set('artifactId', artifactId);
        coordinates.set('version', version);
        coordinates.set('classifier', classifier);
        coordinates.set('extension', extension);
        return new ComponentIdentifier(MAVEN, coordinates);
    }
}

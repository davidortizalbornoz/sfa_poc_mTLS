export interface CityCoordinates {
  latitude: number;
  longitude: number;
}

export interface City {
  id: string;
  name: string;
  region: string;
  province: string;
  population: number;
  foundedYear: number;
  areaKm2: number;
  coordinates: CityCoordinates;
  climate: string;
  economicActivity: string;
  highlights: string[];
  notableFacts: string[];
  unescoSite: boolean;
}

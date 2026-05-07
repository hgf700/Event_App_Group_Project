import { HttpClient } from '@angular/common/http';
import { HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { getAuthHeaders } from '../helpers/GetAuthHeaders';
import {eventDto} from '../Dto/eventDto'

@Injectable({ providedIn: 'root' })
export class SeedService {
  private apiUrl = 'https://localhost:7051/api/v1/Event';
  event: eventDto[] = [];

  constructor(
    private http: HttpClient
  ) {}

  getEvents(){
    return this.http.get<eventDto[]>(
      `${this.apiUrl}/get-events`,
      { headers: getAuthHeaders() }
    );
  }

  eventDetails(id: number){
    return this.http.get<eventDto>(
      `${this.apiUrl}/event-details/${id}`,
      { headers: getAuthHeaders() }
    );
  }


  searchEvent(city: string){
    let params = new HttpParams().set('city', city);

    return this.http.get<eventDto[]>(
      `${this.apiUrl}/event-details`,
      {
        headers: getAuthHeaders(),
        params
      }
    );
  }

  seedDataBase() {
    return this.http.post(
      `${this.apiUrl}/seed-database`,
      {},
      { headers: getAuthHeaders() }
    );
  }
}
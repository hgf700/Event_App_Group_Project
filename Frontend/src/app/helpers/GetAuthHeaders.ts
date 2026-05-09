import { HttpHeaders } from '@angular/common/http';

export function getAuthHeaders(): HttpHeaders {
  const token = localStorage.getItem('jwt');

  if (!token) {
    return new HttpHeaders();
  }

  return new HttpHeaders({
    Authorization: `Bearer ${token}`,
  });
}

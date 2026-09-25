import { ActivatedRoute, Router } from '@angular/router';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class UserNavigationService  {

    constructor(
    private router: Router,
  ) {}

  editCurrentUser(): Promise<boolean> {
    return this.router.navigate(['/edit-user']);
  }

  userBoughtTickets(): Promise<boolean> {
    return this.router.navigate(['/user-tickets']);
  }

  
}
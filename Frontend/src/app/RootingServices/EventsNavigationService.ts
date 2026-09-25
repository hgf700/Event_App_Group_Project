import { ActivatedRoute, Router } from '@angular/router';
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class EventsNavigationService  {

    constructor(
    private router: Router,
  ) {}

  adminPanel(): Promise<boolean> {
    return this.router.navigate(['/admin-panel']);
  }

  goToEvents(): Promise<boolean> {
    return this.router.navigate(['/get-events']);
  }

  seedDatabase(): Promise<boolean>  {
    return this.router.navigate(['/seed-database']);
  }

  searchAndDownloadEvents(): Promise<boolean>  {
    return this.router.navigate(['/search-and-import-events']);
  }
}
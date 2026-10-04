import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { EventService } from '../../Services/EventService';
import { SearchOrDownloadEventService } from '../../Services/SearchOrDownloadEventService';
import { AdminService } from '../../Services/AdminService';

@Component({
  selector: 'app-seed-database',
  imports: [CommonModule, RouterModule],
  templateUrl: './seed-database.html',
  styleUrl: './seed-database.css',
})
export class SeedDatabase implements OnInit {
  loading = false;

  constructor(
    private eventService: EventService,
    private searchOrDownloadEventService: SearchOrDownloadEventService,
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.seedDataBase();
  }

  seedDataBase() {
    this.loading = true;
    this.adminService.seedDataBase().subscribe({
      next: (data) => {
        console.log('seedDataBase');
        console.log(data);
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        alert('Nie udało się seedDataBase');
      },
    });
  }
}

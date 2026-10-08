import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { DatePipe } from '@angular/common';
import { AdminService } from '../../../Services/AdminService';
import { getEventAdminDto } from '../../../Dto/getEventAdminDto';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './events.html',
  styleUrl: './events.css',
})
export class Events implements OnInit {
  events: getEventAdminDto[] = [];
  loading = false;

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadEvents();
  }

  loadEvents(): void {
    this.loading = true;
    this.adminService.getEvents().subscribe({
      next: (response) => {
        this.loading = false;
        this.events = response;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
      },
    });
  }

  deleteEvent(id: number): void {
    if (!confirm('Czy na pewno chcesz usunąć to wydarzenie?')) {
      return;
    }

    this.adminService.deleteEvent(id).subscribe({
      next: () => {
        this.events = this.events.filter((e) => e.id !== id);
      },
      error: (err) => {
        console.error(err);
        alert('Nie udało się usunąć wydarzenia.');
      },
    });
  }
}

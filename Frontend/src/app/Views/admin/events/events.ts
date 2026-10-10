import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { DatePipe } from '@angular/common';
import { AdminService } from '../../../Services/AdminService';
import { getEventAdminDto } from '../../../Dto/getEventAdminDto';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [DatePipe, FormsModule],
  templateUrl: './events.html',
  styleUrl: './events.css',
})
export class Events implements OnInit {
  events: getEventAdminDto[] = [];
  loading = false;

  searchText = '';
  filteredEvents: getEventAdminDto[] = [];

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
        this.filteredEvents = [...response]; // pokaż wszystkie na początku
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
      },
    });
  }

  filterUsers(): void {
    const search = this.searchText.toLowerCase().trim();

    this.filteredEvents = this.events.filter(event =>
      (event.city ?? '').toLowerCase().includes(search) ||
      (event.nameOfClub ?? '').toLowerCase().includes(search) ||
      (event.nameOfEvent ?? '').toLowerCase().includes(search)
    );
  }

  clearSearch() {
    this.searchText = '';
    this.filteredEvents = this.events;
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

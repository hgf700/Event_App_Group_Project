import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { AdminService } from '../../../Services/AdminService';
import { getBookmarkDto } from '../../../Dto/getBookmarkDto';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-bookmarks',
  imports: [FormsModule],
  templateUrl: './bookmarks.html',
  styleUrl: './bookmarks.css',
})
export class Bookmarks implements OnInit {
  bookmarks: getBookmarkDto[] = [];
  loading = false;
  searchText = '';
  filteredBookmarks: getBookmarkDto[] = [];

  constructor(
    private adminService: AdminService,
    private cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.loadBookmarks();
  }

  loadBookmarks(): void {
    this.loading = true;
    this.adminService.adminGetAllBookmarks().subscribe({
      next: (response) => {
        this.bookmarks = response;
        this.loading = false;
        this.filteredBookmarks = [...response];
        this.cdr.detectChanges();
      },
      error: (error) => {
        console.error('Error loading bookmarks:', error);
        this.loading = false;
      },
    });
  }

  filterBookmarks(): void {
    const search = this.searchText.toLowerCase().trim();

    this.filteredBookmarks = this.bookmarks.filter(
      (event) =>
        (event.eventName ?? '').toLowerCase().includes(search) ||
        (event.userId ?? '').toLowerCase().includes(search),
    );
  }

  clearSearch() {
    this.searchText = '';
    this.filteredBookmarks = this.bookmarks;
  }
}

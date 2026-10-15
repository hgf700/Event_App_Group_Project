import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { SubEventDetails } from '../sub-event-details/sub-event-details';
import { MatPaginatorModule } from '@angular/material/paginator';
import { PageEvent } from '@angular/material/paginator';
import { getEventDto } from '../../../Dto/getEventDto';
import { EventService } from '../../../Services/EventService';
import { BookMarkService } from '../../../Services/BookMarkService';
import { getBookmarkDto } from '../../../Dto/getBookmarkDto';

@Component({
  selector: 'app-get-events',
  standalone: true,
  imports: [CommonModule, RouterModule, MatDialogModule, MatPaginatorModule],
  templateUrl: './get-events.html',
  styleUrl: './get-events.css',
})
export class GetEvents implements OnInit {
  events: getEventDto[] = [];
  loading = false;
  totalItems = 0;
  pageSize = 10;
  pageIndex = 0;
  bookmarkedEventIds = new Set<number>();
  bookmarkLoadingIds = new Set<number>();

  constructor(
    private router: Router,
    private cdr: ChangeDetectorRef,
    private eventService: EventService,
    private bookMarkService: BookMarkService,
    private dialog: MatDialog,
  ) {}

  ngOnInit(): void {
    this.loadEvents();
    this.loadUserBookmarks();
  }

  eventDetails(eventId: number) {
    const dialogRef = this.dialog.open(SubEventDetails, {
      width: '600px',
      height: '400px',
      data: {
        eventId,
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      console.log('Dialog closed:', result);
    });
  }

  onPageChange(event: PageEvent) {
    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;

    this.loadEvents();
  }

  loadEvents(): void {
    this.eventService.getEvents(this.pageIndex + 1, this.pageSize).subscribe((response) => {
      this.events = response.data;
      this.totalItems = response.totalCount;
      this.cdr.detectChanges();
    });
  }

  returnToLoginCallback() {
    this.router.navigate(['/login-callback']);
  }

  loadUserBookmarks(): void {
    this.bookMarkService.getUserBookmakrs().subscribe({
    next: (bookmarks: getBookmarkDto[]) => {
      this.bookmarkedEventIds = new Set(
        bookmarks.map(bookmark => bookmark.eventId)
      );

      this.cdr.detectChanges();
    },
    error: (error) => {
      console.error('Błąd pobierania zakładek:', error);
    }
  });
}

isBookmarked(eventId: number): boolean {
  return this.bookmarkedEventIds.has(eventId);
}

bookmarkEvent(eventId: number): void {
  if (
    this.bookmarkedEventIds.has(eventId) ||
    this.bookmarkLoadingIds.has(eventId)
  ) {
    return;
  }

  this.bookmarkLoadingIds.add(eventId);

  this.bookMarkService.bookmarkEvent(eventId).subscribe({
    next: () => {
      this.bookmarkedEventIds.add(eventId);
      this.bookmarkLoadingIds.delete(eventId);
      this.cdr.detectChanges();
    },
    error: (error) => {
      console.error('Błąd zapisywania zakładki:', error);
      this.bookmarkLoadingIds.delete(eventId);
      this.cdr.detectChanges();
    }
  });
}

removeBookmark(eventId: number): void {
  if (
    !this.bookmarkedEventIds.has(eventId) ||
    this.bookmarkLoadingIds.has(eventId)
  ) {
    return;
  }

  this.bookmarkLoadingIds.add(eventId);

  this.bookMarkService.unBookmarkEvent(eventId).subscribe({
    next: () => {
      this.bookmarkedEventIds.delete(eventId);
      this.bookmarkLoadingIds.delete(eventId);
      this.cdr.detectChanges();
    },
    error: (error) => {
      console.error('Błąd usuwania zakładki:', error);
      this.bookmarkLoadingIds.delete(eventId);
      this.cdr.detectChanges();
    }
  });
}
}

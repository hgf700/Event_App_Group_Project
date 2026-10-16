import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { getBookmarkDto } from '../../../Dto/getBookmarkDto';
import { BookMarkService } from '../../../Services/BookMarkService';

@Component({
  selector: 'app-user-bookmark',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './user-bookmark.html',
  styleUrl: './user-bookmark.css',
})
export class UserBookmark implements OnInit {
  userBookmark: getBookmarkDto[] = [];

  loading = false;
  errorMessage = '';
  removingEventId: number | null = null;

  constructor(
    private cdr: ChangeDetectorRef,
    private bookMarkService: BookMarkService,
  ) {}

  ngOnInit(): void {
    this.loadBOokamrks();
  }

  loadBOokamrks(): void {
    this.loading = true;
    this.errorMessage = '';

    this.bookMarkService.getUserBookmarks().subscribe({
      next: (response: getBookmarkDto[]) => {
        this.userBookmark = response ?? [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (error) => {
        console.error('Błąd pobierania zakładek:', error);

        this.loading = false;
        this.cdr.detectChanges();
      },
    });
  }

  removeBookmark(eventId: number): void {
    if (this.removingEventId !== null) {
      return;
    }

    this.removingEventId = eventId;

    this.bookMarkService.unBookmarkEvent(eventId).subscribe({
      next: () => {
        this.userBookmark = this.userBookmark.filter(
          (bookmark: any) => bookmark.eventId !== eventId,
        );

        this.removingEventId = null;
        this.cdr.detectChanges();
      },
      error: (error) => {
        console.error('Błąd usuwania zakładki:', error);

        this.errorMessage = 'Nie udało się usunąć zakładki.';
        this.removingEventId = null;
        this.cdr.detectChanges();
      },
    });
  }
}

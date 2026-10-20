import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { of } from 'rxjs';
import { describe, it, expect, beforeEach, vi } from 'vitest';

import { GetEvents } from './get-events';
import { EventService } from '../../../Services/EventService';
import { BookMarkService } from '../../../Services/BookMarkService';
import { getEventDto } from '../../../Dto/getEventDto';
import { getBookmarkDto } from '../../../Dto/getBookmarkDto';

describe('GetEvents', () => {
  let component: GetEvents;
  let fixture: ComponentFixture<GetEvents>;

  const mockEvents = [
    {
      eventId: 1,
      nameOfEvent: 'Summer Festival',
      typeOfEvent: 'Koncert',
      startOfEvent: '2026-08-15T18:00:00',
      nameOfClub: 'Klub Muzyczny',
      city: 'Bielsko-Biała',
      country: 'Polska',
      photoUrl: '',
    },
    {
      eventId: 2,
      nameOfEvent: 'Music Night',
      typeOfEvent: 'Impreza',
      startOfEvent: '2026-08-20T20:00:00',
      nameOfClub: 'Klub Testowy',
      city: 'Katowice',
      country: 'Polska',
      photoUrl: '',
    },
  ] as unknown as getEventDto[];

  const mockBookmarks = [{ eventId: 1 }] as getBookmarkDto[];

  const eventServiceMock = {
    getEvents: vi.fn(),
  };

  const bookmarkServiceMock = {
    getUserBookmarks: vi.fn(),
    bookmarkEvent: vi.fn(),
    unBookmarkEvent: vi.fn(),
  };

  const routerMock = {
    navigate: vi.fn().mockResolvedValue(true),
  };

  const dialogMock = {
    open: vi.fn(),
  };

  beforeEach(async () => {
    vi.clearAllMocks();

    eventServiceMock.getEvents.mockReturnValue(
      of({
        data: mockEvents,
        totalCount: 25,
      }),
    );

    bookmarkServiceMock.getUserBookmarks.mockReturnValue(of(mockBookmarks));

    bookmarkServiceMock.bookmarkEvent.mockReturnValue(of({}));
    bookmarkServiceMock.unBookmarkEvent.mockReturnValue(of({}));

    await TestBed.configureTestingModule({
      imports: [GetEvents],
      providers: [
        { provide: EventService, useValue: eventServiceMock },
        { provide: BookMarkService, useValue: bookmarkServiceMock },
        { provide: Router, useValue: routerMock },
        { provide: MatDialog, useValue: dialogMock },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(GetEvents);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load the first page on initialization', () => {
    expect(eventServiceMock.getEvents).toHaveBeenCalledWith(1, 10);
  });

  it('should load user bookmarks on initialization', () => {
    expect(bookmarkServiceMock.getUserBookmarks).toHaveBeenCalled();
    expect(component.isBookmarked(1)).toBe(true);
    expect(component.isBookmarked(2)).toBe(false);
  });

  it('should assign events and total count', () => {
    expect(component.events).toEqual(mockEvents);
    expect(component.totalItems).toBe(25);
  });

  it('should display events in the template', () => {
    const element: HTMLElement = fixture.nativeElement;

    expect(element.textContent).toContain('Summer Festival');
    expect(element.textContent).toContain('Music Night');
  });

  it('should load the next page when pagination changes', () => {
    component.onPageChange({
      pageIndex: 1,
      pageSize: 10,
      length: 25,
      previousPageIndex: 0,
    });

    expect(component.pageIndex).toBe(1);
    expect(component.pageSize).toBe(10);
    expect(eventServiceMock.getEvents).toHaveBeenLastCalledWith(2, 10);
  });

  it('should handle a page size change', () => {
    component.onPageChange({
      pageIndex: 0,
      pageSize: 25,
      length: 25,
      previousPageIndex: 0,
    });

    expect(component.pageSize).toBe(25);
    expect(eventServiceMock.getEvents).toHaveBeenLastCalledWith(1, 25);
  });

  it('should navigate to login callback', () => {
    component.returnToLoginCallback();

    expect(routerMock.navigate).toHaveBeenCalledWith(['/login-callback']);
  });

  it('should bookmark an event', () => {
    component.bookmarkEvent(2);

    expect(bookmarkServiceMock.bookmarkEvent).toHaveBeenCalledWith(2);
    expect(component.isBookmarked(2)).toBe(true);
    expect(component.bookmarkLoadingIds.has(2)).toBe(false);
  });

  it('should remove a bookmark', () => {
    component.removeBookmark(1);

    expect(bookmarkServiceMock.unBookmarkEvent).toHaveBeenCalledWith(1);
    expect(component.isBookmarked(1)).toBe(false);
    expect(component.bookmarkLoadingIds.has(1)).toBe(false);
  });

  it('should not bookmark an event that is already bookmarked', () => {
    component.bookmarkEvent(1);

    expect(bookmarkServiceMock.bookmarkEvent).not.toHaveBeenCalled();
  });

  it('should not remove a bookmark that does not exist', () => {
    component.removeBookmark(2);

    expect(bookmarkServiceMock.unBookmarkEvent).not.toHaveBeenCalled();
  });
});

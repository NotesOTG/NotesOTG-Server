using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NotesOTG_Server.Models;
using NotesOTG_Server.Models.Contexts;
using NotesOTG_Server.Models.Http.Requests;
using NotesOTG_Server.Models.Http.Responses;
using NotesOTG_Server.Models.Http.Responses.impl;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NotesOTG_Server.Services.Data.Impl
{
    public class NotesService : Service<Notes>
    {
        /**
         * Work on retreiving notes like every 5 seconds 
         **/
        private readonly UserService _userService;

        public NotesService(DatabaseContext conext, ILogger<NotesService> logger, UserService userService) : base(conext, logger)
        {
            _userService = userService;
        }

        public async Task<List<NoteResponse>> GetAllNotes()
        {
            var user = await _userService.GetUser();
            if (user == null)
            {
                return null;
            }
            
            var notes = entity.Include(u => u.UserId).Where(n => n.UserId.Id == user.Id);
            return (List<NoteResponse>)notes;
        }

        public async Task<NoteResponse> AddNote(NotesRequest request)
        {
            var user = await _userService.GetUser();
            if (user== null)
            {
                return new NoteResponse { Success = false, Error = "Currently not signed in." };
            }

            var notesOBJ = new Notes {
                Body = request.Body,
                Category = request.Category,
                CheckList = request.CheckList,
                PublicId = Guid.NewGuid().ToString(),
                CreationDate = DateTime.Parse(request.CreationDate),
                ModifiedDate = DateTime.Parse(request.ModifiedDate),
                CustomCategory = request.CustomCategory,
                Title = request.Title,
                UserId = user
            };
            
            if (await Add(notesOBJ) != null)
            {
                await Save();
                return new NoteResponse { Success = true, PublicId = notesOBJ.PublicId };
            }
            return new NoteResponse { Success = false, Error = "Couldn't save note."};
        }

        public async Task<BasicResponse> DeleteNote(string publicNoteId)
        {
            var user = await _userService.GetUser();
            if (user == null)
            {
                return new NoteResponse { Success = false, Error = "Currently not signed in." };
            }

            var note = await entity.Include(u => u.UserId).FirstOrDefaultAsync(id => id.PublicId == publicNoteId);
            if (note != null && note.UserId.Id == user.Id)
            {
                Remove(note);
                await Save();
                return new BasicResponse { Success = note != null };
            }
            return new BasicResponse { Success = note != null, Error = "Couldn't delete note. Make sure you are signed in."};
        }

        public async Task<NoteResponse> UpdateNote(NotesRequest request)
        {
            var user = await _userService.GetUser();
            if (user == null)
            {
                return new NoteResponse { Success = false, Error = "Currently not signed in." };
            }

            var note = await entity.FirstOrDefaultAsync(id => id.PublicId == request.PublicId);
            if (note == null)
            {
                return new NoteResponse { Success = false, Error = "Not is found found, can't update note." };
            }

            note.Title = request.Title;
            note.ModifiedDate = DateTime.Parse(request.ModifiedDate);
            note.Body = request.Body;
            note.CustomCategory = request.CustomCategory;
            note.Category = request.Category;
            note.CheckList = request.CheckList;
            await Save();

            return new NoteResponse { Success = true, Title = note.Title, Body = note.Body, Category = note.Category, ModifiedDate = note.ModifiedDate.ToString(), CheckList = note.CheckList, CustomCategory = note.CustomCategory };
        }

    }
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "types.h"
#include "oschar.h"
#include "smdh.h"
#include "bannerutil/stb_image.h"


#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

#ifdef WIN32
static inline char* FixMinGWPath(char* buf)
{
	if (*buf == '/')
	{
		buf[0] = buf[1];
		buf[1] = ':';
	}
	return buf;
}
#else
#define FixMinGWPath(_arg) (_arg)
#endif

struct sArgInfo
{
	char* input_png;
	char* output_smdh;
	char* name;
	char* description;
	char* author;
};

class SmdhBuilder
{
public:
	SmdhBuilder()
	{
	
	}
	~SmdhBuilder()
	{

	}

	int BuildSmdh(const struct sArgInfo& args)
	{
		args_ = args;

		safe_call(MakeAppTitles());
		safe_call(MakeIconData());
		safe_call(SetIconSettings());
		safe_call(WriteToFile());

		return 0;
	}

private:
	struct sArgInfo args_;
	Smdh smdh_;

	int MakeAppTitles()
	{		
		utf16char_t* name;
		utf16char_t* description;
		utf16char_t* author;

		// create UTF-16 copy of short title
		name = strcopy_8to16((args_.name == NULL) ? "Sample Homebrew" : args_.name);
		if (name == NULL || utf16_strlen(name) > 0x40)
		{
			die("[ERROR] Name is too long.");
		}
		
		os_fputs(name, stdout);
		printf("\n");

		// create UTF-16 copy of long title
		description = strcopy_8to16((args_.description == NULL) ? "Sample Homebrew" : args_.description);
		if (description == NULL || utf16_strlen(description) > 0x80)
		{
			free(name);
			die("[ERROR] Description is too long.");
		}
		
		os_fputs(description, stdout);
		printf("\n");

		// create UTF-16 copy of publisher
		author = strcopy_8to16((args_.author == NULL) ? "" : args_.author);
		if (author == NULL || utf16_strlen(author) > 0x40)
		{
			free(name);
			free(description);
			die("[ERROR] Author name is too long.");
		}

		smdh_.SetTitle(Smdh::SMDH_TITLE_JAPANESE, name, description, author);
		smdh_.SetTitle(Smdh::SMDH_TITLE_ENGLISH, name, description, author);
		return 0;
	}

	int SetIconSettings()
	{
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_CERO, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_ESRB, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_USK, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_PEGI_GEN, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_PEGI_PRT, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_PEGI_BBFC, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_COB, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_GRB, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);
		smdh_.SetAgeRestriction(Smdh::SMDH_RATING_AGENCY_CGSRR, 0, Smdh::SMDH_AGE_RATING_FLAG_NO_RESTRICTION);

		smdh_.SetFlag(Smdh::SMDH_FLAG_VISABLE || Smdh::SMDH_FLAG_RECORD_USAGE);
		
		smdh_.SetRegionLockout(Smdh::SMDH_REGION_ALL);

		return 0;
	}

	u16 PackColour(u8 r, u8 g, u8 b, u8 a)
	{
			float alpha = a / 255.0f;
			r = (u8)(r * alpha) >> 3;
			g = (u8)(g * alpha) >> 2;
			b = (u8)(b * alpha) >> 3;
			return (r << 11) | (g << 5) | b;
	}


	void GetTiledIconData(u16* out, u8* in, int height, int width)
	{
		static const u8 TILE_ORDER[64] = 
		{ 
			0,  1,  8,  9,  2,  3,  10, 11, 16, 17, 24, 25, 18, 19, 26, 27,
			4,  5,  12, 13, 6,  7,  14, 15, 20, 21, 28, 29, 22, 23, 30, 31,
			32, 33, 40, 41, 34, 35, 42, 43, 48, 49, 56, 57, 50, 51, 58, 59,
			36, 37, 44, 45, 38, 39, 46, 47, 52, 53, 60, 61, 54, 55, 62, 63 
		};

		u32 n = 0;

		for (int y = 0; y < height; y += 8) {
			for (int x = 0; x < width; x += 8) {
				for (int k = 0; k < 8 * 8; k++) {
					u32 xx = (u32)(TILE_ORDER[k] & 0x7);
					u32 yy = (u32)(TILE_ORDER[k] >> 3);

					u8* pixel = in + (((y + yy) * width + (x + xx)) * 4);
					out[n++] = PackColour(pixel[0], pixel[1], pixel[2], pixel[3]);
				}
			}
		}
	}

	int MakeIconData()
	{
		u8* img;
		int img_width, img_height, img_depth;
		u16 small_icon[24 * 24] = { 0 };
		u16 large_icon[48 * 48] = { 0 };


		// get large icon
		if ((img = stbi_load(args_.input_png, &img_width, &img_height, &img_depth, STBI_rgb_alpha)) == NULL)
		{
			fprintf(stderr, "[ERROR] Failed to decode image. (%s)\n", stbi_failure_reason());
			return 1;
		}

		if (img_width != 48 || img_height != 48 || img_depth != STBI_rgb_alpha)
		{
			die("[ERROR] Decoded image has invalid properties.");
		}

		GetTiledIconData(large_icon, img, 48, 48);
		
		// get small icon from large icon
		u8 img_24_data[24 * 24 * 4] = { 0 };
		int i1, i2, i3, i4, id;
		u8 r1, r2, r3, r4;
		u8 g1, g2, g3, g4;
		u8 b1, b2, b3, b4;
		u8 a1, a2, a3, a4;
		for (int y = 0; y < img_height; y += 2) {
			for (int x = 0; x < img_width; x += 2) {
				i1 = (y * 48 + x) * 4;
				r1 = img[i1 + 0];
				g1 = img[i1 + 1];
				b1 = img[i1 + 2];
				a1 = img[i1 + 3];

				i2 = (y * 48 + (x + 1)) * 4;
				r2 = img[i2 + 0];
				g2 = img[i2 + 1];
				b2 = img[i2 + 2];
				a2 = img[i2 + 3];

				i3 = ((y + 1) * 48 + x) * 4;
				r3 = img[i3 + 0];
				g3 = img[i3 + 1];
				b3 = img[i3 + 2];
				a3 = img[i3 + 3];

				i4 = ((y + 1) * 48 + (x + 1)) * 4;
				r4 = img[i4 + 0];
				g4 = img[i4 + 1];
				b4 = img[i4 + 2];
				a4 = img[i4 + 3];

				id = ((y / 2) * 24 + (x / 2)) * 4;
				img_24_data[id + 0] = (u8)((r1 + r2 + r3 + r4) / 4);
				img_24_data[id + 1] = (u8)((g1 + g2 + g3 + g4) / 4);
				img_24_data[id + 2] = (u8)((b1 + b2 + b3 + b4) / 4);
				img_24_data[id + 3] = (u8)((a1 + a2 + a3 + a4) / 4);
			}
		}
		GetTiledIconData(small_icon, img_24_data, 24, 24);
		
		smdh_.SetIconData(small_icon, large_icon);
		return 0;
	}

	int WriteToFile()
	{
		FILE* fp;
	
		if ((fp = fopen(args_.output_smdh, "wb")) == NULL)
		{
			die("[ERROR] Failed to create output file.");
		}

		if (smdh_.data_size() == 0 || smdh_.data_blob() == NULL)
		{
			die("[ERROR] Failed to generate smdh data.");
		}

		fwrite(smdh_.data_blob(), 1, smdh_.data_size(), fp);

		fclose(fp);

		return 0;
	}
};



int usage(const char *prog_name)
{
	fprintf(stderr,
		"Usage:\n"
		"    %s <input.png> <output.smdh> [options]\n\n"
		"Options:\n"
		"    --name=value        : Specify title name\n"
		"    --description=value : Specify title descripton\n"
		"    --author=value      : Specify author\n"
		, prog_name);
	return 1;
}

int ParseArgs(struct sArgInfo& info, int argc, char **argv)
{
	// clear struct
	memset((u8*)&info, 0, sizeof(struct sArgInfo));

	// return if minimum requirements not met
	if (argc < 3)
	{
		return usage(argv[0]);
	}

	info.input_png = FixMinGWPath(argv[1]);
	info.output_smdh = FixMinGWPath(argv[2]);

	char *arg, *value;

	for (int i = 3; i < argc; i++)
	{
		arg = argv[i];
		if (strncmp(arg, "--", 2) != 0)
		{
			return usage(argv[0]);
		}

		// skip over "--" to get name of argument
		arg += 2;

		// get argument value
		value = strchr(arg, '=');

		// check there is actually an argument value
		if (value == NULL || value[1] == '\0')
		{
			return usage(argv[0]);
		}

		// skip over "=", overwriting it to null byte
		*value++ = '\0';

		if (strcmp(arg, "name") == 0)
		{
			info.name = value;
		}
		else if (strcmp(arg, "description") == 0)
		{
			info.description = value;
		}
		else if (strcmp(arg, "author") == 0)
		{
			info.author = value;
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown argument: %s\n", arg);
			return usage(argv[0]);
		}
	}

	return 0;
}

int main(int argc, char** argv)
{
	struct sArgInfo args;
	SmdhBuilder smdh;

	safe_call(ParseArgs(args, argc, argv));
	safe_call(smdh.BuildSmdh(args));

	return 0;
}